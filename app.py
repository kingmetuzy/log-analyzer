import os
import re
import io
import csv
import json
import hmac
import hashlib
import secrets
import sqlite3
import time
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urljoin

import requests
from flask import (
    Flask, request, render_template_string, redirect, url_for,
    session, flash, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "")
if not app.secret_key:
    # Development fallback only. Set SECRET_KEY in Render for stable secure sessions.
    app.secret_key = secrets.token_hex(32)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
ALLOWED_EXTENSIONS = {".txt", ".log"}
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_BASE_URL = "https://api.paystack.co"
APP_BASE_URL = os.environ.get("APP_BASE_URL", "").strip().rstrip("/")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "").strip()
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "").strip()
APP_BASE_URL = APP_BASE_URL or "https://log-analyzer-wroa.onrender.com"

# Temporary server-side analysis storage avoids putting uploaded logs in browser cookies.
# Entries expire after 30 minutes and are not written to the database.
ANALYSES = {}
ANALYSES_LOCK = threading.Lock()
ANALYSIS_TTL_SECONDS = 30 * 60
ANALYSIS_MAX_ENTRIES = 100

# Prices are stored in kobo. Change them here if you decide on different prices.
PLANS = {
    "monthly": {
        "name": "Pro Monthly", "amount": 1_500_000, "currency": "NGN",
        "duration_days": 30, "display": "₦15,000 / month",
        # Public Paystack plan code (not a secret key).
        "paystack_plan_code": "PLN_qg6mx0wgfe9q5zz",
    },
    "yearly": {
        "name": "Pro Yearly", "amount": 15_000_000, "currency": "NGN",
        "duration_days": 365, "display": "₦150,000 / year",
        # Public Paystack plan code (not a secret key).
        "paystack_plan_code": "PLN_8y8phcju2t310ia",
    },
}
FREE_FEATURES = [
    "Upload .txt and .log files (up to 2 MB)",
    "Count errors, warnings, information and other lines",
    "Search and filter log messages",
]
PRO_FEATURES = [
    "Everything in Free",
    "Download CSV reports",
    "Save verified Pro access for the subscription period",
    "Priority access to future Pro tools",
]

# This app supports PostgreSQL via DATABASE_URL or SQLite locally.
# For Render production, use a managed PostgreSQL database for durable user/payment records.
def db_connection():
    if DATABASE_URL.startswith(("postgres://", "postgresql://")):
        import psycopg
        from psycopg.rows import dict_row
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        return conn, "postgres"
    path = os.environ.get("SQLITE_PATH", "log_analyzer.db")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"

def db_execute(conn, db_kind, sql, params=()):
    if db_kind == "postgres":
        sql = sql.replace("?", "%s")
    return conn.execute(sql, params)

def init_db():
    conn, kind = db_connection()
    try:
        if kind == "postgres":
            db_execute(conn, kind, """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            db_execute(conn, kind, """
                CREATE TABLE IF NOT EXISTS payments (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id),
                    reference TEXT UNIQUE NOT NULL,
                    plan_key TEXT NOT NULL,
                    amount BIGINT NOT NULL,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    paid_at TEXT,
                    expires_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            db_execute(conn, kind, """
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id),
                    subscription_code TEXT UNIQUE NOT NULL,
                    plan_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    next_payment_date TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            db_execute(conn, kind, """
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id),
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
        else:
            db_execute(conn, kind, """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            db_execute(conn, kind, """
                CREATE TABLE IF NOT EXISTS payments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    reference TEXT UNIQUE NOT NULL,
                    plan_key TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    paid_at TEXT,
                    expires_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            db_execute(conn, kind, """
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    subscription_code TEXT UNIQUE NOT NULL,
                    plan_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    next_payment_date TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            db_execute(conn, kind, """
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
        conn.commit()
    finally:
        conn.close()

init_db()

def utc_now():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()

def parse_dt(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn, kind = db_connection()
    try:
        row = db_execute(conn, kind, "SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def active_pro(user_id):
    if not user_id:
        return False
    conn, kind = db_connection()
    try:
        row = db_execute(conn, kind, """
            SELECT expires_at FROM payments
            WHERE user_id = ? AND status = 'success'
            ORDER BY expires_at DESC LIMIT 1
        """, (user_id,)).fetchone()
        expiry = parse_dt(row["expires_at"]) if row else None
        return bool(expiry and expiry > utc_now())
    finally:
        conn.close()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please create an account or log in first.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "is_pro": active_pro(session.get("user_id")),
        "csrf_token": csrf_token,
        "plans": PLANS,
        "free_features": FREE_FEATURES,
        "pro_features": PRO_FEATURES,
    }

@app.before_request
def protect_post_requests():
    # Paystack webhooks authenticate with their HMAC signature, not browser CSRF tokens.
    if request.endpoint == "paystack_webhook":
        return
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not sent or not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="Security check failed. Refresh the page and try again.")


def clean_analyses():
    now = time.monotonic()
    with ANALYSES_LOCK:
        expired = [key for key, value in ANALYSES.items() if now - value["created"] > ANALYSIS_TTL_SECONDS]
        for key in expired:
            ANALYSES.pop(key, None)
        if len(ANALYSES) > ANALYSIS_MAX_ENTRIES:
            oldest = sorted(ANALYSES, key=lambda key: ANALYSES[key]["created"])
            for key in oldest[:len(ANALYSES) - ANALYSIS_MAX_ENTRIES]:
                ANALYSES.pop(key, None)

def get_last_analysis():
    analysis_id = session.get("last_analysis_id")
    if not analysis_id:
        return None
    with ANALYSES_LOCK:
        item = ANALYSES.get(analysis_id)
        if item and time.monotonic() - item["created"] <= ANALYSIS_TTL_SECONDS:
            return item
        ANALYSES.pop(analysis_id, None)
    session.pop("last_analysis_id", None)
    return None

def send_reset_email(email, reset_url):
    """Send a password reset email through Brevo's transactional email API."""
    if not BREVO_API_KEY or not BREVO_SENDER_EMAIL:
        raise RuntimeError("Brevo email delivery is not configured")
    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": BREVO_API_KEY,
                "content-type": "application/json",
            },
            json={
                "sender": {"name": "Log Analyzer Pro", "email": BREVO_SENDER_EMAIL},
                "to": [{"email": email}],
                "subject": "Reset your Log Analyzer Pro password",
                "textContent": (
                    "We received a request to reset your Log Analyzer Pro password.\n\n"
                    f"Use this link within 30 minutes: {reset_url}\n\n"
                    "If you did not request this, you can ignore this email."
                ),
            },
            timeout=(4, 10),
        )
    except requests.RequestException as exc:
        app.logger.exception("Brevo password-reset request failed due to a network/timeout error.")
        raise RuntimeError("Brevo request failed") from exc
    if not response.ok:
        # Log the provider's diagnostic response, but never log API keys or reset links.
        app.logger.error("Brevo password-reset API rejected the request: HTTP %s; response=%s",
                         response.status_code, response.text[:500])
        raise RuntimeError(f"Brevo email API returned HTTP {response.status_code}")
    app.logger.info("Brevo accepted a password-reset email request (HTTP %s).", response.status_code)

def base_template(content):
    return r"""
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title or "Log Analyzer Pro" }}</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c31;--muted:#aab6d0;--text:#f2f5ff;--line:#293653;--blue:#3978e8;--green:#1c9b72}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
.wrap{max-width:1080px;margin:auto;padding:22px 14px 40px}header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:clamp(25px,5vw,35px);margin:0}h2{font-size:20px;margin:0 0 12px}h3{margin:0 0 6px}.muted{color:var(--muted)}.nav{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
a{color:#9cc2ff}.button,button{display:inline-block;background:var(--blue);color:white;border:0;border-radius:9px;padding:10px 14px;font:inherit;text-decoration:none;cursor:pointer}
.secondary{background:#34415b}.green{background:var(--green)}.panel,.card{background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:17px;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.price{font-size:27px;font-weight:750;margin:8px 0}.badge{background:#20345c;color:#c8dcff;border:1px solid #35548b;border-radius:999px;padding:5px 10px;font-size:12px}
input,select{width:100%;max-width:100%;padding:11px 12px;margin:5px 0 12px;border-radius:9px;border:1px solid var(--line);background:#0c1427;color:var(--text);font:inherit}
input[type=file]{padding:8px}label{font-weight:600}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row>*{flex:0 1 auto}
.notice{padding:12px 14px;border-radius:10px;margin:10px 0;background:#16342e;border:1px solid #28685c}.notice.error{background:#3a2029;border-color:#814052}
.stat{font-size:28px;font-weight:750}.log{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--line);border-left:4px solid #7f8aa7;border-radius:8px;padding:10px;margin:8px 0}.errorline{border-left-color:#ff667e;background:#2b1824}.warningline{border-left-color:#ffc857;background:#302919}.infoline{border-left-color:#4bd4a3;background:#142b29}
li{margin:5px 0}.footer{text-align:center;color:var(--muted);font-size:12px;margin-top:28px}
@media(max-width:600px){.wrap{padding:16px 11px 30px}.panel,.card{padding:14px}.price{font-size:24px}}
</style></head><body><div class="wrap">
<header><div><h1>📊 Log Analyzer Pro</h1><div class="muted">Understand your application logs faster.</div></div>
<nav class="nav"><a class="button secondary" href="/">Analyzer</a><a class="button secondary" href="/pricing">Pricing</a>
{% if current_user %}<span class="badge">{{ current_user.email }}</span><a class="button secondary" href="/account">Account</a>
<form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary" type="submit">Log out</button></form>
{% else %}<a class="button secondary" href="/login">Log in</a><a class="button" href="/register">Create account</a>{% endif %}
</nav></header>
{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<div class="notice {{ category }}">{{ message }}</div>{% endfor %}{% endwith %}
""" + content + r"""
<div class="footer">Log Analyzer Pro · Only analyze logs you are authorized to access. Do not upload passwords, access tokens, or sensitive personal data.</div>
</div></body></html>
"""

HOME_CONTENT = r"""
<section class="panel"><span class="badge">{% if is_pro %}PRO ACTIVE{% else %}FREE PLAN{% endif %}</span>
<h2 style="margin-top:12px">Upload and analyze a log file</h2>
<p class="muted">Upload a .txt or .log file up to 2 MB. Files are analyzed for this request and are not shared with other users.</p>
<form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label for="logfile">Choose log file</label><input id="logfile" type="file" name="logfile" accept=".txt,.log,text/plain" required>
<button type="submit">Upload &amp; analyze</button></form></section>
{% if analyzed %}
<section class="grid"><div class="card"><div class="muted">Total lines</div><div class="stat">{{ stats.total }}</div></div><div class="card"><div class="muted">Errors</div><div class="stat">{{ stats.errors }}</div></div><div class="card"><div class="muted">Warnings</div><div class="stat">{{ stats.warnings }}</div></div><div class="card"><div class="muted">Info / other</div><div class="stat">{{ stats.info_other }}</div></div></section>
<section class="panel"><h2>Search and filter</h2><form method="get" class="row"><input style="flex:2" name="q" value="{{ query }}" placeholder="Search log text"><select style="flex:1" name="level"><option value="ALL" {% if level=='ALL' %}selected{% endif %}>All levels</option><option value="ERROR" {% if level=='ERROR' %}selected{% endif %}>Errors</option><option value="WARNING" {% if level=='WARNING' %}selected{% endif %}>Warnings</option><option value="INFO" {% if level=='INFO' %}selected{% endif %}>Info</option></select><button>Apply</button></form>
<p class="muted">Showing {{ shown }} of {{ stats.total }} lines.</p>
{% for item in logs %}<div class="log {{ item.kind }}">{{ item.text }}</div>{% else %}<p class="muted">No matching lines.</p>{% endfor %}
{% if advice %}<section class="panel"><h2>Automatic explanations and suggested fixes</h2><p class="muted">These are general troubleshooting suggestions based on matching text in your logs. Confirm the cause before changing a production system.</p>
{% for item in advice %}<div class="card" style="margin:10px 0"><strong>{{ item.title }}</strong><p>{{ item.explanation }}</p><strong>Suggested checks</strong><ul>{% for step in item.steps %}<li>{{ step }}</li>{% endfor %}</ul><p class="muted">Matched log: {{ item.line }}</p></div>{% endfor %}</section>{% endif %}
{% if is_pro %}<a class="button green" href="/report.csv">Download CSV report</a>{% else %}<p class="muted">CSV export is a Pro feature. <a href="/pricing">Upgrade to Pro</a>.</p>{% endif %}
</section>{% endif %}
"""

@app.route("/", methods=["GET", "POST"])
def home():
    message = ""
    raw_lines = None
    if request.method == "POST":
        upload = request.files.get("logfile")
        if not upload or not upload.filename:
            flash("Choose a .txt or .log file first.", "error")
        else:
            filename = secure_filename(upload.filename)
            if os.path.splitext(filename)[1].lower() not in ALLOWED_EXTENSIONS:
                flash("Only .txt and .log files are supported.", "error")
            else:
                content = upload.read(app.config["MAX_CONTENT_LENGTH"] + 1)
                if len(content) > app.config["MAX_CONTENT_LENGTH"]:
                    flash("File too large. Maximum size is 2 MB.", "error")
                else:
                    raw_lines = content.decode("utf-8", errors="replace").splitlines()
                    clean_analyses()
                    analysis_id = secrets.token_urlsafe(24)
                    with ANALYSES_LOCK:
                        ANALYSES[analysis_id] = {"lines": raw_lines, "filename": filename, "created": time.monotonic()}
                    session.pop("last_upload_lines", None)
                    session.pop("last_upload_name", None)
                    session["last_analysis_id"] = analysis_id
                    flash(f"Loaded {len(raw_lines)} lines from {filename}.", "success")
                    return redirect(url_for("home"))
    analysis = get_last_analysis()
    raw_lines = analysis["lines"] if analysis else None
    analyzed = raw_lines is not None
    if not analyzed:
        return render_template_string(base_template(HOME_CONTENT), title="Log Analyzer Pro", analyzed=False,
                                      stats={"total": 0, "errors": 0, "warnings": 0, "info_other": 0},
                                      logs=[], shown=0, query="", level="ALL")
    def classify(line):
        upper = line.upper()
        if re.search(r"\b(ERROR|FATAL|CRITICAL|EXCEPTION)\b", upper): return "errorline"
        if re.search(r"\b(WARN|WARNING)\b", upper): return "warningline"
        if re.search(r"\b(INFO|DEBUG|NOTICE)\b", upper): return "infoline"
        return "otherline"
    counts = [classify(x) for x in raw_lines]
    stats = {"total": len(raw_lines), "errors": counts.count("errorline"), "warnings": counts.count("warningline"),
             "info_other": counts.count("infoline") + counts.count("otherline")}

    # Rule-based guidance: no external AI service or log data sharing required.
    advice = []
    guidance_rules = [
        (r"database connection failed|could not connect to database|connection refused.*database",
         "Database connection problem",
         "The application could not establish a connection to its database. Common causes include an unavailable database, incorrect connection settings, or a network/access issue.",
         ["Confirm the database service is running.", "Check the host, port, database name, and environment variables without exposing passwords.", "Check network access and database permissions.", "Review nearby log entries for the underlying error."]),
        (r"memory usage is high|out of memory|memoryerror|oomkilled",
         "High memory usage",
         "The process may be running low on available memory or using more memory than expected.",
         ["Check current memory usage and recent changes in workload.", "Look for repeated tasks or unusually large files/requests.", "Review system/container memory limits and restart history.", "Avoid increasing limits until you understand the cause."]),
        (r"login failed|authentication failed|invalid password|unauthorized|401\b",
         "Login or authentication failure",
         "A login or authenticated request was rejected. This may be caused by incorrect credentials, expired sessions, or access rules.",
         ["Check the timestamp and whether the attempt was expected.", "Verify the login flow and account status.", "Check authentication configuration and session expiry.", "Do not put passwords, tokens, or other secrets in logs."]),
        (r"permission denied|forbidden|access denied|403\b",
         "Permission or access problem",
         "The application attempted to access a resource without sufficient permission.",
         ["Check the user or service account permissions.", "Confirm file, folder, API, or database access rules.", "Verify the request is using the intended account."]),
        (r"timeout|timed out|deadline exceeded",
         "Timeout",
         "An operation took longer than the allowed time or did not respond in time.",
         ["Check whether the dependent service is healthy.", "Review network latency and response times.", "Look for slow database queries or overloaded services.", "Only adjust timeout settings after identifying the slow operation."]),
        (r"file not found|no such file or directory|filenotfounderror",
         "File not found",
         "The application could not find a file or path it expected.",
         ["Check that the file exists at the expected path.", "Check spelling, working directory, and file permissions.", "Confirm the file is included in the deployed environment."]),
    ]
    for line in raw_lines:
        upper_line = line.upper()
        if classify(line) not in {"errorline", "warningline"}:
            continue
        for pattern, title, explanation, steps in guidance_rules:
            if re.search(pattern, line, re.IGNORECASE):
                advice.append({"title": title, "explanation": explanation, "steps": steps, "line": line[:500]})
                break
    query = request.args.get("q", "").strip()[:200]
    level = request.args.get("level", "ALL").upper()
    if level not in {"ALL", "ERROR", "WARNING", "INFO"}: level = "ALL"
    kind_to_level = {"errorline": "ERROR", "warningline": "WARNING", "infoline": "INFO", "otherline": "OTHER"}
    logs = []
    for line in raw_lines:
        kind = classify(line)
        if (level == "ALL" or kind_to_level[kind] == level) and query.lower() in line.lower():
            logs.append({"text": line, "kind": kind})
    return render_template_string(base_template(HOME_CONTENT), title="Log Analyzer Pro", analyzed=True,
                                  stats=stats, logs=logs, shown=len(logs), query=query, level=level, advice=advice)

AUTH_CONTENT = r"""
<section class="panel" style="max-width:520px;margin:25px auto"><h2>{{ heading }}</h2><p class="muted">{{ helper }}</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required maxlength="254">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="{{ autocomplete }}" minlength="10" required>
<button type="submit">{{ action }}</button></form>{% if title == "Log in" %}<p><a href="{{ url_for('forgot_password') }}">Forgot password?</a></p>{% endif %}<p class="muted">{{ switch_text }} <a href="{{ switch_url }}">{{ switch_label }}</a></p></section>
"""

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user(): return redirect(url_for("account"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
            flash("Enter a valid email address.", "error")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
        else:
            conn, kind = db_connection()
            try:
                db_execute(conn, kind, "INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)",
                           (email, generate_password_hash(password), iso(utc_now())))
                conn.commit()
                row = db_execute(conn, kind, "SELECT id,email FROM users WHERE email = ?", (email,)).fetchone()
                session.clear()
                session["user_id"] = row["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                flash("Account created. You can use the Free plan or choose Pro.", "success")
                return redirect(url_for("pricing"))
            except Exception as exc:
                if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                    flash("An account with that email already exists. Please log in.", "error")
                else:
                    app.logger.exception("Registration failed")
                    flash("We couldn't create your account. Please try again.", "error")
            finally:
                conn.close()
    return render_template_string(base_template(AUTH_CONTENT), title="Create account", heading="Create your account",
        helper="Create an account to manage your plan and payments.", action="Create account",
        autocomplete="new-password", switch_text="Already have an account?", switch_url=url_for("login"), switch_label="Log in")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user(): return redirect(url_for("account"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn, kind = db_connection()
        try:
            row = db_execute(conn, kind, "SELECT id,email,password_hash FROM users WHERE email = ?", (email,)).fetchone()
        finally:
            conn.close()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("account"))
        flash("Email or password is incorrect.", "error")
    return render_template_string(base_template(AUTH_CONTENT), title="Log in", heading="Welcome back",
        helper="Log in to view your account and Pro access.", action="Log in", autocomplete="current-password",
        switch_text="New here?", switch_url=url_for("register"), switch_label="Create account")


FORGOT_CONTENT = r"""
<section class="panel" style="max-width:520px;margin:25px auto"><h2>Forgot your password?</h2>
<p class="muted">Enter the email address associated with your account. If it exists, we will send a reset link.</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required maxlength="254">
<button type="submit">Send reset link</button></form><p><a href="{{ url_for('login') }}">Back to log in</a></p></section>
"""

RESET_CONTENT = r"""
<section class="panel" style="max-width:520px;margin:25px auto"><h2>Choose a new password</h2>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<label for="password">New password</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="10" required>
<label for="confirm_password">Confirm new password</label><input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" minlength="10" required>
<button type="submit">Reset password</button></form></section>
"""

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        # Use a generic message so the page does not reveal whether an account exists.
        generic = "If an account matches that email and email delivery is configured, a reset link will be sent shortly."
        app.logger.info("Password-reset request received.")
        conn, kind = db_connection()
        try:
            user = db_execute(conn, kind, "SELECT id,email FROM users WHERE LOWER(email) = ?", (email,)).fetchone()
            app.logger.info("Password-reset account lookup completed; matching account found=%s.", bool(user))
            if user:
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                expires = iso(utc_now() + timedelta(minutes=30))
                db_execute(conn, kind, "INSERT INTO password_reset_tokens(token_hash,user_id,expires_at,used_at,created_at) VALUES(?,?,?,?,?)",
                           (token_hash, user["id"], expires, None, iso(utc_now())))
                conn.commit()
                reset_url = urljoin(APP_BASE_URL + "/", "reset-password/" + token)
                try:
                    send_reset_email(user["email"], reset_url)
                except Exception:
                    app.logger.exception("Password-reset email delivery failed. Check the Brevo sender, API key, and Brevo transactional email status in Render/Brevo.")
                    # Do not reveal account existence or the token to the browser.
        except Exception:
            app.logger.exception("Password-reset database operation failed.")
            flash("We could not process the request right now. Please try again later.", "error")
            return redirect(url_for("forgot_password"))
        finally:
            conn.close()
        flash(generic, "success")
        return redirect(url_for("login"))
    return render_template_string(base_template(FORGOT_CONTENT), title="Forgot password")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if not token or len(token) > 200:
        abort(404)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn, kind = db_connection()
    try:
        reset = db_execute(conn, kind, "SELECT token_hash,user_id,expires_at,used_at FROM password_reset_tokens WHERE token_hash = ?", (token_hash,)).fetchone()
        valid = bool(reset and not reset["used_at"] and parse_dt(reset["expires_at"]) and parse_dt(reset["expires_at"]) > utc_now())
        if not valid:
            if request.method == "GET":
                flash("That password reset link is invalid, expired, or already used. Request a new one.", "error")
                return redirect(url_for("forgot_password"))
            abort(400)
        if request.method == "POST":
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if len(password) < 10:
                flash("Use a password with at least 10 characters.", "error")
            elif password != confirm:
                flash("The passwords do not match.", "error")
            else:
                db_execute(conn, kind, "UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), reset["user_id"]))
                db_execute(conn, kind, "UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ?", (iso(utc_now()), token_hash))
                conn.commit()
                flash("Your password has been reset. Please log in with your new password.", "success")
                return redirect(url_for("login"))
    finally:
        conn.close()
    return render_template_string(base_template(RESET_CONTENT), title="Reset password")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("home"))

@app.route("/pricing")
def pricing():
    content = r"""
<section class="panel"><h2>Choose your plan</h2><p class="muted">Start free, or upgrade to unlock CSV export. Pro access lasts for the purchased period.</p>
<div class="grid"><article class="card"><h3>Free</h3><div class="price">₦0</div><ul>{% for feature in free_features %}<li>{{ feature }}</li>{% endfor %}</ul><a class="button secondary" href="/">Use Free</a></article>
{% for key,plan in plans.items() %}<article class="card"><span class="badge">PRO</span><h3 style="margin-top:10px">{{ plan.name }}</h3><div class="price">{{ plan.display }}</div><ul>{% for feature in pro_features %}<li>{{ feature }}</li>{% endfor %}</ul>
{% if current_user %}<form method="post" action="/checkout/{{ key }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="green" type="submit">Upgrade to {{ plan.name }}</button></form>{% else %}<a class="button green" href="/register">Create account to upgrade</a>{% endif %}
</article>{% endfor %}</div>
<p class="muted">Payments are processed by Paystack. By choosing a Pro plan, you authorize recurring charges of the displayed amount at the displayed interval until you cancel. Pro access is granted only after server-side payment verification. If you cancel, access remains active until the paid period ends.</p></section>
"""
    return render_template_string(base_template(content), title="Pricing")

@app.route("/account")
@login_required
def account():
    user = current_user()
    conn, kind = db_connection()
    try:
        rows = db_execute(conn, kind, """
            SELECT plan_key, amount, currency, status, paid_at, expires_at, created_at
            FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 20
        """, (user["id"],)).fetchall()
        payments = [dict(x) for x in rows]
        sub_row = db_execute(conn, kind, """
            SELECT subscription_code, plan_key, status, next_payment_date
            FROM subscriptions WHERE user_id = ?
            ORDER BY updated_at DESC LIMIT 1
        """, (user["id"],)).fetchone()
        subscription = dict(sub_row) if sub_row else None
    finally:
        conn.close()
    content = r"""
<section class="panel"><h2>Your account</h2><p>Email: <strong>{{ user.email }}</strong></p>
{% if is_pro %}<div class="notice">Your Pro access is active.</div>{% else %}<p>Your account is currently on the Free plan.</p><a class="button green" href="/pricing">View Pro plans</a>{% endif %}</section>
{% if subscription %}<section class="panel"><h2>Subscription</h2><p>Status: <strong>{{ subscription.status|replace('-', ' ')|title }}</strong></p>
{% if subscription.next_payment_date %}<p class="muted">Next payment date: {{ subscription.next_payment_date }}</p>{% endif %}
{% if subscription.status in ['active', 'non-renewing', 'attention'] %}<a class="button secondary" href="{{ url_for('manage_subscription') }}">Manage or cancel subscription</a>{% endif %}
<p class="muted">If you cancel, your Pro access remains available until the paid period ends.</p></section>{% endif %}
<section class="panel"><h2>Payment history</h2>{% if payments %}<div style="overflow-x:auto"><table><thead><tr><th>Plan</th><th>Amount</th><th>Status</th><th>Paid at</th><th>Expires</th></tr></thead><tbody>{% for p in payments %}<tr><td>{{ plans[p.plan_key].name if p.plan_key in plans else p.plan_key }}</td><td>{{ p.currency }} {{ '%.2f'|format(p.amount/100) }}</td><td>{{ p.status }}</td><td>{{ p.paid_at or '—' }}</td><td>{{ p.expires_at or '—' }}</td></tr>{% endfor %}</tbody></table></div>{% else %}<p class="muted">No payments yet.</p>{% endif %}</section>
"""
    return render_template_string(base_template(content), title="Your account", user=user, payments=payments, subscription=subscription)

def paystack_headers():
    if not PAYSTACK_SECRET_KEY:
        raise RuntimeError("PAYSTACK_SECRET_KEY is not configured")
    return {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}

@app.route("/subscription/manage")
@login_required
def manage_subscription():
    """Redirect the signed-in customer to Paystack's secure subscription manager."""
    if not PAYSTACK_SECRET_KEY:
        flash("Subscription management is temporarily unavailable. Please try again later.", "error")
        return redirect(url_for("account"))
    user = current_user()
    conn, kind = db_connection()
    try:
        row = db_execute(conn, kind, """
            SELECT subscription_code FROM subscriptions
            WHERE user_id = ? AND status IN ('active', 'non-renewing', 'attention')
            ORDER BY updated_at DESC LIMIT 1
        """, (user["id"],)).fetchone()
        subscription_code = row["subscription_code"] if row else None
    finally:
        conn.close()
    if not subscription_code:
        flash("No manageable subscription was found for your account yet.", "error")
        return redirect(url_for("account"))
    try:
        response = requests.get(
            PAYSTACK_BASE_URL + "/subscription/" + requests.utils.quote(subscription_code, safe="") + "/manage/link",
            headers=paystack_headers(), timeout=20,
        )
        result = response.json() if response.content else {}
        link = (result.get("data") or {}).get("link") if isinstance(result, dict) else None
        if not response.ok or not result.get("status") or not link or not link.startswith("https://paystack.com/"):
            app.logger.warning("Paystack subscription management link failed: status=%s", response.status_code)
            flash("Paystack could not open subscription management. Please try again later.", "error")
            return redirect(url_for("account"))
        return redirect(link)
    except (requests.RequestException, ValueError, RuntimeError):
        app.logger.exception("Subscription management link request failed")
        flash("We couldn't reach Paystack to manage your subscription. Please try again later.", "error")
        return redirect(url_for("account"))


def public_base_url():
    if APP_BASE_URL:
        return APP_BASE_URL
    # Render normally supplies RENDER_EXTERNAL_URL; use it when APP_BASE_URL is absent.
    return os.environ.get("RENDER_EXTERNAL_URL", "").strip().rstrip("/")

@app.route("/checkout/<plan_key>", methods=["POST"])
@login_required
def checkout(plan_key):
    plan = PLANS.get(plan_key)
    if not plan:
        abort(404)
    if not PAYSTACK_SECRET_KEY:
        flash("Payments are not configured yet. Please try again later.", "error")
        return redirect(url_for("pricing"))
    base_url = public_base_url()
    if not base_url:
        flash("APP_BASE_URL is missing in Render. Add your live website URL and retry.", "error")
        return redirect(url_for("pricing"))
    user = current_user()
    reference = "lap_" + secrets.token_urlsafe(20).replace("-", "").replace("_", "")
    conn, kind = db_connection()
    try:
        db_execute(conn, kind, """
            INSERT INTO payments(user_id,reference,plan_key,amount,currency,status,created_at)
            VALUES(?,?,?,?,?,'pending',?)
        """, (user["id"], reference, plan_key, plan["amount"], plan["currency"], iso(utc_now())))
        conn.commit()
    finally:
        conn.close()
    plan_code = plan.get("paystack_plan_code", "").strip()
    if not plan_code.startswith("PLN_"):
        flash("The recurring Paystack plan is not configured correctly. Please try again later.", "error")
        return redirect(url_for("pricing"))
    payload = {
        "email": user["email"],
        "amount": plan["amount"],
        "plan": plan_code,
        "currency": plan["currency"],
        "reference": reference,
        "callback_url": urljoin(base_url + "/", "payment/callback"),
        "metadata": {
            "user_id": str(user["id"]),
            "plan_key": plan_key,
            "custom_fields": [
                {"display_name": "Plan", "variable_name": "plan", "value": plan["name"]}
            ],
        },
    }
    try:
        response = requests.post(PAYSTACK_BASE_URL + "/transaction/initialize",
                                 headers=paystack_headers(), json=payload, timeout=20)
        if not response.ok:
            # Log status and safe response details; never log authorization headers or secret keys.
            app.logger.warning("Paystack initialization failed: status=%s response=%s",
                               response.status_code, response.text[:800])
            flash("Paystack could not start checkout. Please check the payment settings or try again later.", "error")
            return redirect(url_for("pricing"))
        result = response.json()
        if not result.get("status") or not result.get("data", {}).get("authorization_url"):
            app.logger.warning("Paystack initialization returned an unexpected response: %s", json.dumps(result)[:800])
            flash("Paystack did not return a checkout link. Please try again later.", "error")
            return redirect(url_for("pricing"))
        return redirect(result["data"]["authorization_url"])
    except requests.RequestException:
        app.logger.exception("Paystack initialization network error")
        flash("We couldn't reach Paystack. Please try again later.", "error")
        return redirect(url_for("pricing"))
    except (ValueError, RuntimeError):
        app.logger.exception("Paystack configuration or response error")
        flash("Payment settings need attention. Please try again later.", "error")
        return redirect(url_for("pricing"))

def verify_paystack(reference):
    response = requests.get(PAYSTACK_BASE_URL + "/transaction/verify/" + requests.utils.quote(reference, safe=""),
                            headers=paystack_headers(), timeout=20)
    if not response.ok:
        app.logger.warning("Paystack verification failed: status=%s response=%s", response.status_code, response.text[:800])
        return None
    data = response.json()
    if not data.get("status"):
        return None
    return data.get("data")

def apply_verified_payment(reference, verified):
    if not verified or verified.get("status") != "success":
        return False, "Payment is not marked successful by Paystack."
    conn, kind = db_connection()
    try:
        # Serialize duplicate deliveries for the same payment. SQLite's immediate
        # transaction also serializes writers; PostgreSQL locks the payment row.
        if kind == "sqlite":
            conn.execute("BEGIN IMMEDIATE")
        row_sql = "SELECT * FROM payments WHERE reference = ?"
        if kind == "postgres":
            row_sql += " FOR UPDATE"
        row = db_execute(conn, kind, row_sql, (reference,)).fetchone()
        if not row:
            app.logger.warning("Verified Paystack reference has no matching local payment")
            return False, "We couldn't match this payment to an order."
        payment = dict(row)
        plan = PLANS.get(payment["plan_key"])
        if not plan:
            return False, "The selected plan is invalid."
        if str(verified.get("reference", "")) != reference:
            return False, "Payment reference did not match."
        try:
            verified_amount = int(verified.get("amount", -1))
        except (TypeError, ValueError):
            verified_amount = -1
        if verified_amount != int(payment["amount"]):
            app.logger.warning("Paystack amount mismatch for reference %s", reference)
            return False, "The payment amount did not match the selected plan."
        if verified.get("currency") != payment["currency"]:
            app.logger.warning("Paystack currency mismatch for reference %s", reference)
            return False, "The payment currency did not match the selected plan."
        if payment["status"] == "success":
            conn.commit()
            return True, "Payment already verified."
        if kind == "postgres":
            # Lock the customer row too, so separate successful payments cannot
            # calculate overlapping Pro expiry periods for the same account.
            db_execute(conn, kind, "SELECT id FROM users WHERE id = ? FOR UPDATE", (payment["user_id"],)).fetchone()
        now = utc_now()
        existing_expiry_row = db_execute(conn, kind, """
            SELECT expires_at FROM payments WHERE user_id = ? AND status = 'success'
            ORDER BY expires_at DESC LIMIT 1
        """, (payment["user_id"],)).fetchone()
        previous_expiry = parse_dt(existing_expiry_row["expires_at"]) if existing_expiry_row else None
        start = previous_expiry if previous_expiry and previous_expiry > now else now
        expires = start + timedelta(days=plan["duration_days"])
        db_execute(conn, kind, """
            UPDATE payments SET status='success', paid_at=?, expires_at=? WHERE reference=?
        """, (iso(now), iso(expires), reference))
        conn.commit()
        return True, "Payment verified. Your Pro access is active."
    except Exception:
        conn.rollback()
        app.logger.exception("Could not record verified payment")
        return False, "We verified the payment response but could not update your account. Please contact support."
    finally:
        conn.close()


@app.route("/payment/callback")
@login_required
def payment_callback():
    reference = request.args.get("reference", "").strip()
    if not reference or len(reference) > 200:
        flash("Payment reference is missing.", "error")
        return redirect(url_for("account"))
    try:
        verified = verify_paystack(reference)
        ok, message = apply_verified_payment(reference, verified)
        flash(message, "success" if ok else "error")
    except requests.RequestException:
        app.logger.exception("Payment callback verification network error")
        flash("We couldn't verify the payment right now. Check your account again shortly.", "error")
    except (RuntimeError, ValueError):
        app.logger.exception("Payment callback configuration error")
        flash("Payment verification is temporarily unavailable.", "error")
    return redirect(url_for("account"))


def _plan_key_from_payload(*objects):
    """Identify one of this app's plans from Paystack's plan code or amount/currency."""
    plan_code = None
    amount = None
    currency = None
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        plan = obj.get("plan") or obj.get("plan_object")
        if isinstance(plan, dict):
            plan_code = plan_code or plan.get("plan_code")
            amount = amount if amount is not None else plan.get("amount")
            currency = currency or plan.get("currency")
        elif isinstance(plan, str):
            plan_code = plan_code or plan
        if not plan_code:
            plan_code = obj.get("plan_code")
        if amount is None and obj.get("amount") is not None:
            amount = obj.get("amount")
        currency = currency or obj.get("currency")
    for key, plan in PLANS.items():
        if plan_code and str(plan.get("paystack_plan_code")) == str(plan_code):
            return key
    try:
        amount_int = int(amount) if amount is not None else None
    except (TypeError, ValueError):
        amount_int = None
    matches = [key for key, plan in PLANS.items()
               if amount_int == int(plan["amount"]) and currency == plan["currency"]]
    return matches[0] if len(matches) == 1 else None


def _customer_email_from_payload(*objects):
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        customer = obj.get("customer")
        if isinstance(customer, dict):
            email = customer.get("email")
            if isinstance(email, str) and email.strip():
                return email.strip().lower()
        email = obj.get("email")
        if isinstance(email, str) and email.strip():
            return email.strip().lower()
    return ""


def process_subscription_event(event_name, data):
    """Store subscription lifecycle status without removing already-paid access."""
    if not isinstance(data, dict):
        return False
    subscription_obj = data.get("subscription") if isinstance(data.get("subscription"), dict) else {}
    plan_obj = data.get("plan") if isinstance(data.get("plan"), dict) else {}
    email = _customer_email_from_payload(data, subscription_obj)
    subscription_code = (data.get("subscription_code") or subscription_obj.get("subscription_code") or "").strip()
    plan_key = _plan_key_from_payload(data, subscription_obj, plan_obj)
    if not subscription_code:
        app.logger.warning("Paystack subscription event %s had no subscription code", event_name)
        return False

    status_by_event = {
        "subscription.create": data.get("status") or "active",
        "subscription.not_renew": "non-renewing",
        "subscription.disable": data.get("status") or "disabled",
        "invoice.payment_failed": "attention",
    }
    status = str(status_by_event.get(event_name, data.get("status") or "unknown")).lower()
    next_payment_date = data.get("next_payment_date") or subscription_obj.get("next_payment_date")
    conn, kind = db_connection()
    try:
        existing = db_execute(conn, kind, "SELECT id FROM subscriptions WHERE subscription_code = ?", (subscription_code,)).fetchone()
        if existing:
            db_execute(conn, kind, """
                UPDATE subscriptions SET status=?, next_payment_date=?, updated_at=?
                WHERE subscription_code=?
            """, (status, next_payment_date, iso(utc_now()), subscription_code))
            conn.commit()
            return True
        if not email:
            app.logger.warning("Paystack subscription event %s had no customer email for an unknown subscription", event_name)
            return False
        user = db_execute(conn, kind, "SELECT id FROM users WHERE LOWER(email)=?", (email,)).fetchone()
        if not user:
            app.logger.warning("Paystack subscription email did not match a Log Analyzer Pro user")
            return False
        if not plan_key:
            # Do not guess the plan if neither plan code nor unique amount identifies it.
            app.logger.warning("Paystack subscription event %s could not be matched to a configured plan", event_name)
            return False
        now = iso(utc_now())
        db_execute(conn, kind, """
            INSERT INTO subscriptions(user_id,subscription_code,plan_key,status,next_payment_date,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?)
        """, (user["id"], subscription_code, plan_key, status, next_payment_date, now, now))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        app.logger.exception("Could not record Paystack subscription event %s", event_name)
        return False
    finally:
        conn.close()


def apply_recurring_renewal(reference, verified, event_data=None):
    """Record only a server-verified renewal, safely handling retries and concurrent events."""
    if not verified or verified.get("status") != "success":
        return False
    if str(verified.get("reference", "")) != reference:
        return False
    try:
        amount = int(verified.get("amount", -1))
    except (TypeError, ValueError):
        return False
    currency = verified.get("currency")
    event_data = event_data if isinstance(event_data, dict) else {}
    plan_key = _plan_key_from_payload(verified, event_data)
    if not plan_key or int(PLANS[plan_key]["amount"]) != amount or PLANS[plan_key]["currency"] != currency:
        app.logger.info("Recurring charge %s did not match a configured plan; no access granted", reference)
        return False
    email = _customer_email_from_payload(verified, event_data)
    if not email:
        return False

    conn, kind = db_connection()
    try:
        if kind == "sqlite":
            conn.execute("BEGIN IMMEDIATE")
        existing = db_execute(conn, kind, "SELECT status FROM payments WHERE reference = ?", (reference,)).fetchone()
        if existing:
            conn.commit()
            return existing["status"] == "success"
        user_row = db_execute(conn, kind, "SELECT id FROM users WHERE LOWER(email) = ?", (email,)).fetchone()
        if not user_row:
            app.logger.warning("Recurring Paystack payment email did not match a Log Analyzer Pro user")
            return False
        user_id = user_row["id"]
        if kind == "postgres":
            # Serializes separate renewal references for the same customer so expiry periods cannot overlap.
            db_execute(conn, kind, "SELECT id FROM users WHERE id = ? FOR UPDATE", (user_id,)).fetchone()
        now = utc_now()
        last = db_execute(conn, kind, """
            SELECT expires_at FROM payments WHERE user_id = ? AND status = 'success'
            ORDER BY expires_at DESC LIMIT 1
        """, (user_id,)).fetchone()
        previous_expiry = parse_dt(last["expires_at"]) if last else None
        start = previous_expiry if previous_expiry and previous_expiry > now else now
        expires = start + timedelta(days=PLANS[plan_key]["duration_days"])
        db_execute(conn, kind, """
            INSERT INTO payments(user_id,reference,plan_key,amount,currency,status,paid_at,expires_at,created_at)
            VALUES(?,?,?,?,?,'success',?,?,?)
        """, (user_id, reference, plan_key, amount, currency, iso(now), iso(expires), iso(now)))
        conn.commit()
        app.logger.info("Recorded recurring Paystack renewal for user_id=%s plan=%s", user_id, plan_key)
        return True
    except Exception:
        conn.rollback()
        # A unique-reference conflict means another delivery already recorded it.
        try:
            existing = db_execute(conn, kind, "SELECT status FROM payments WHERE reference = ?", (reference,)).fetchone()
            if existing and existing["status"] == "success":
                return True
        except Exception:
            pass
        app.logger.exception("Could not record recurring Paystack renewal")
        return False
    finally:
        conn.close()


@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    if not PAYSTACK_SECRET_KEY:
        abort(503)
    signature = request.headers.get("x-paystack-signature", "")
    raw_body = request.get_data()
    expected = hmac.new(PAYSTACK_SECRET_KEY.encode(), raw_body, hashlib.sha512).hexdigest()
    if not signature or not hmac.compare_digest(signature, expected):
        abort(401)
    try:
        event = json.loads(raw_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        abort(400)
    event_name = event.get("event") if isinstance(event, dict) else None
    data = event.get("data") if isinstance(event, dict) else None
    if not isinstance(data, dict):
        return "OK", 200

    if event_name == "charge.success":
        reference = str(data.get("reference") or "").strip()
        if reference:
            try:
                verified = verify_paystack(reference)
                if verified:
                    conn, kind = db_connection()
                    try:
                        existing = db_execute(conn, kind, "SELECT reference FROM payments WHERE reference = ?", (reference,)).fetchone()
                    finally:
                        conn.close()
                    if existing:
                        ok, _message = apply_verified_payment(reference, verified)
                        if not ok:
                            app.logger.warning("Verified first-payment event was not applied for reference %s", reference)
                    else:
                        apply_recurring_renewal(reference, verified, data)
            except (requests.RequestException, RuntimeError):
                app.logger.exception("Paystack charge verification failed; webhook will be retried")
                return "Temporary processing error", 500
            except Exception:
                app.logger.exception("Webhook payment processing failed")
                return "Temporary processing error", 500
    elif event_name in {"subscription.create", "subscription.not_renew", "subscription.disable", "invoice.payment_failed"}:
        if not process_subscription_event(event_name, data):
            # Avoid infinite retries for unrelated/unknown customer events; log the mismatch for review.
            app.logger.warning("Subscription webhook event %s was not linked to a local subscription", event_name)
    return "OK", 200

@app.route("/report.csv")
@login_required
def download_report():
    if not active_pro(session.get("user_id")):
        flash("CSV export is available on Pro. Choose a plan to unlock it.", "error")
        return redirect(url_for("pricing"))
    analysis = get_last_analysis()
    lines = analysis["lines"] if analysis else None
    if lines is None:
        flash("Upload a log file before downloading a report. Analyses expire after 30 minutes or a server restart.", "error")
        return redirect(url_for("home"))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Line number", "Level", "Log message"])
    for number, line in enumerate(lines, start=1):
        upper = line.upper()
        level = "ERROR" if re.search(r"\b(ERROR|FATAL|CRITICAL|EXCEPTION)\b", upper) else (
            "WARNING" if re.search(r"\b(WARN|WARNING)\b", upper) else (
                "INFO" if re.search(r"\b(INFO|DEBUG|NOTICE)\b", upper) else "OTHER"
            )
        )
        writer.writerow([number, level, line])
    data = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    return send_file(data, mimetype="text/csv", as_attachment=True,
                     download_name=f"log-analysis-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv")

@app.route("/health")
def health():
    return {"status": "ok"}

@app.errorhandler(400)
def bad_request(error):
    return render_template_string(base_template(r"<section class='panel'><h2>Request could not be processed</h2><p>{{ message }}</p><a class='button' href='/'>Return home</a></section>"),
                                  title="Request error", message=getattr(error, "description", "Bad request")), 400

@app.errorhandler(413)
def too_large(_error):
    return "File too large. Maximum size is 2 MB.", 413

@app.errorhandler(500)
def internal_error(_error):
    app.logger.exception("Unhandled application error")
    return "Something went wrong. Please try again later.", 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
