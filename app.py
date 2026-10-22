from flask import Flask, request, render_template_string, send_file
from collections import Counter
from werkzeug.utils import secure_filename
import os
import io
import re
import csv
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json
import secrets
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit
ALLOWED_EXTENSIONS = {".txt", ".log"}

HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Log Analyzer Pro</title>
  <style>
    :root { color-scheme: dark; --bg:#0b1020; --panel:#141c31; --muted:#9ba8c7; --text:#f2f5ff; --line:#293653; --blue:#6ea8fe; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif; }
    .wrap { max-width:1050px; margin:auto; padding:24px 16px 40px; }
    header { display:flex; justify-content:space-between; gap:16px; align-items:center; flex-wrap:wrap; margin-bottom:22px; }
    h1 { margin:0; font-size:clamp(24px,5vw,34px); }
    .sub { color:var(--muted); margin:5px 0 0; }
    .badge { background:#20345c; color:#b8d3ff; border:1px solid #35548b; padding:6px 10px; border-radius:999px; font-size:12px; }
    .cards { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:18px 0; }
    .card,.panel { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:16px; }
    .label { color:var(--muted); font-size:13px; }
    .num { font-size:28px; font-weight:750; margin-top:4px; overflow-wrap:anywhere; }
    .panel { margin-top:14px; }
    h2 { font-size:18px; margin:0 0 12px; }
    form { margin:0; }
    .row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
    input,select,button,.button { border:1px solid var(--line); border-radius:9px; padding:10px 12px; font:inherit; }
    input,select { background:#0c1427; color:var(--text); max-width:100%; }
    input[type=file] { width:100%; }
    button,.button { background:#2d65c8; color:white; border:0; cursor:pointer; text-decoration:none; display:inline-block; }
    button:hover,.button:hover { filter:brightness(1.12); }
    .secondary { background:#34415b; }
    .notice { padding:11px 13px; border-radius:10px; margin:12px 0; background:#152d2a; border:1px solid #28685c; }
    .error-notice { background:#3a2029; border-color:#814052; }
    .muted { color:var(--muted); }
    .log { border:1px solid var(--line); border-left:4px solid #5a6c8f; border-radius:8px; padding:11px 12px; margin:8px 0; overflow-wrap:anywhere; white-space:pre-wrap; }
    .log.error { border-left-color:#ff667e; background:#2b1824; }
    .log.warning { border-left-color:#ffc857; background:#302919; }
    .log.info { border-left-color:#4bd4a3; background:#142b29; }
    .log.other { border-left-color:#7f8aa7; background:#1b2336; }
    .empty { padding:20px; text-align:center; color:var(--muted); border:1px dashed var(--line); border-radius:10px; }
    .plans { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; }
    .plan { border:1px solid var(--line); background:#101a30; padding:18px; border-radius:12px; }
    .price { font-size:26px; font-weight:750; margin:8px 0; }
    .footer { text-align:center; color:var(--muted); margin-top:24px; font-size:13px; }
    @media(max-width:650px) { .cards { grid-template-columns:repeat(2,minmax(0,1fr)); } .wrap { padding:18px 12px 30px; } .num { font-size:24px; } }
  </style>
</head>
<body>
<div class="wrap">
  <header>
    <div><h1>📊 Log Analyzer Pro</h1><p class="sub">Upload, search, and summarize application logs.</p></div>
    <div class="row"><a class="button secondary" href="/pricing">View Pro plans</a><span class="badge">FLASK • LEVEL 5 PROJECT</span></div>
  </header>

  {% if message %}<div class="notice {% if is_error %}error-notice{% endif %}">{{ message }}</div>{% endif %}

  <section class="cards">
    <div class="card"><div class="label">Total log lines</div><div class="num">{{ stats.total }}</div></div>
    <div class="card"><div class="label">Errors</div><div class="num">{{ stats.errors }}</div></div>
    <div class="card"><div class="label">Warnings</div><div class="num">{{ stats.warnings }}</div></div>
    <div class="card"><div class="label">Info / other</div><div class="num">{{ stats.info_other }}</div></div>
  </section>

  <section class="panel">
    <h2>Upload a log file</h2>
    <form method="post" enctype="multipart/form-data" class="row">
      <input type="file" name="logfile" accept=".txt,.log,text/plain" required>
      <button type="submit">Upload &amp; analyze</button>
    </form>
    <p class="muted">Text files only, maximum 2 MB. Use sample or redacted logs; avoid passwords, tokens, and personal data.</p>
  </section>

  <section class="panel">
    <h2>Search and filter</h2>
    <form method="get" class="row">
      <input name="q" value="{{ query }}" placeholder="Search log text…" aria-label="Search log text">
      <select name="level" aria-label="Filter by log level">
        <option value="ALL" {% if level == 'ALL' %}selected{% endif %}>All levels</option>
        <option value="ERROR" {% if level == 'ERROR' %}selected{% endif %}>Errors</option>
        <option value="WARNING" {% if level == 'WARNING' %}selected{% endif %}>Warnings</option>
        <option value="INFO" {% if level == 'INFO' %}selected{% endif %}>Info</option>
      </select>
      <button type="submit">Apply filters</button>
      <a class="button secondary" href="/">Clear filters</a>
    </form>
  </section>

  <section class="panel">
    <div class="row" style="justify-content:space-between;margin-bottom:10px">
      <h2 style="margin:0">Analysis results</h2>
      <a class="button" href="/report.csv">Download CSV report</a>
    </div>
    <p class="muted">Showing {{ shown }} of {{ stats.total }} lines. Counts are based on the loaded log file.</p>
    {% if logs %}
      {% for item in logs %}
        <div class="log {{ item.kind }}">{{ item.text }}</div>
      {% endfor %}
    {% else %}
      <div class="empty">No log lines match these filters.</div>
    {% endif %}
  </section>
  <div class="footer">Log Analyzer Pro • Built with Flask • Analyze only logs you are authorized to access.</div>
</div>
</body>
</html>
"""

PRICING_HTML = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Log Analyzer Pro plans</title>
<style>body{margin:0;background:#0b1020;color:#f2f5ff;font:16px/1.5 system-ui,sans-serif}.wrap{max-width:850px;margin:auto;padding:24px 16px}.panel{background:#141c31;border:1px solid #293653;border-radius:14px;padding:20px;margin:14px 0}.plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.plan{background:#101a30;border:1px solid #293653;border-radius:12px;padding:18px}.price{font-size:26px;font-weight:750}input{display:block;width:100%;box-sizing:border-box;margin:10px 0;padding:12px;border-radius:8px;border:1px solid #293653;background:#0c1427;color:#fff}button,.button{display:inline-block;background:#2d65c8;color:white;padding:11px 14px;border:0;border-radius:8px;text-decoration:none;cursor:pointer}.muted{color:#9ba8c7}.notice{padding:12px;background:#152d2a;border:1px solid #28685c;border-radius:9px;margin:12px 0}.error{background:#3a2029;border-color:#814052}</style></head><body><div class="wrap"><h1>💎 Log Analyzer Pro</h1><p class="muted">Choose a plan. Payments are processed securely by Paystack.</p>
{% if message %}<div class="notice {% if is_error %}error{% endif %}">{{ message }}</div>{% endif %}
<div class="plans"><div class="plan"><h2>Free</h2><div class="price">₦0</div><p>Use the current log analyzer features.</p><a class="button" href="/">Continue free</a></div><div class="plan"><h2>Pro Monthly</h2><div class="price">₦15,000</div><p>Proposed monthly price. This checkout is a one-time payment, not an automatic recurring subscription.</p></div><div class="plan"><h2>Pro Yearly</h2><div class="price">₦150,000</div><p>Proposed yearly price. This checkout is a one-time payment, not an automatic recurring subscription.</p></div></div>
<div class="panel"><h2>Continue to secure checkout</h2><p class="muted">Enter your email and select a plan. Do not enter your card details on this website; Paystack handles card entry.</p><form method="post" action="/paystack/initialize"><input type="email" name="email" placeholder="Your email address" required maxlength="254"><select name="plan" required style="display:block;width:100%;box-sizing:border-box;margin:10px 0;padding:12px;border-radius:8px;background:#0c1427;color:#fff"><option value="monthly">Pro Monthly — ₦15,000</option><option value="yearly">Pro Yearly — ₦150,000</option></select><button type="submit">Continue to Paystack</button></form></div><p><a class="button" href="/">Back to analyzer</a></p><p class="muted">International/USD checkout is not enabled in this initial version. It depends on your Paystack account's approved currencies and settings.</p></div></body></html>
"""

def classify(line):
    upper = line.upper()
    if re.search(r"\b(ERROR|FATAL|CRITICAL|EXCEPTION)\b", upper):
        return "error"
    if re.search(r"\b(WARN|WARNING)\b", upper):
        return "warning"
    if re.search(r"\b(INFO|DEBUG|NOTICE)\b", upper):
        return "info"
    return "other"

def get_lines():
    path = "mylog.txt"
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as file:
            file.write(
                "INFO: Log Analyzer is ready\n"
                "ERROR: Example database connection failed\n"
                "WARNING: Example high memory usage\n"
                "INFO: Upload a .txt or .log file to analyze\n"
            )
    with open(path, "r", encoding="utf-8", errors="replace") as file:
        return file.readlines()

def analyze():
    lines = get_lines()
    counts = Counter(classify(line) for line in lines)
    return lines, {
        "total": len(lines),
        "errors": counts["error"],
        "warnings": counts["warning"],
        "info_other": counts["info"] + counts["other"],
    }

@app.route("/", methods=["GET", "POST"])
def home():
    message = ""
    is_error = False

    if request.method == "POST":
        uploaded = request.files.get("logfile")
        if not uploaded or not uploaded.filename:
            message, is_error = "Choose a .txt or .log file first.", True
        else:
            filename = secure_filename(uploaded.filename)
            extension = os.path.splitext(filename)[1].lower()
            if extension not in ALLOWED_EXTENSIONS:
                message, is_error = "Unsupported file type. Please upload a .txt or .log file.", True
            else:
                content = uploaded.read()
                if len(content) > app.config["MAX_CONTENT_LENGTH"]:
                    message, is_error = "File is too large. Maximum size is 2 MB.", True
                else:
                    try:
                        decoded = content.decode("utf-8", errors="replace")
                        with open("mylog.txt", "w", encoding="utf-8") as file:
                            file.write(decoded)
                        message = f"Successfully loaded {len(decoded.splitlines())} log lines from {filename}."
                    except OSError:
                        message, is_error = "The uploaded file could not be saved. Please try again.", True

    all_lines, stats = analyze()
    query = request.args.get("q", "").strip()[:200]
    level = request.args.get("level", "ALL").upper()
    if level not in {"ALL", "ERROR", "WARNING", "INFO"}:
        level = "ALL"

    filtered = []
    for line in all_lines:
        kind = classify(line)
        level_match = (
            level == "ALL"
            or (level == "ERROR" and kind == "error")
            or (level == "WARNING" and kind == "warning")
            or (level == "INFO" and kind == "info")
        )
        if level_match and query.lower() in line.lower():
            filtered.append({"text": line.rstrip("\n"), "kind": kind})

    return render_template_string(
        HTML,
        stats=stats,
        logs=filtered,
        shown=len(filtered),
        query=query,
        level=level,
        message=message,
        is_error=is_error,
    )

@app.route("/report.csv", methods=["GET"])
def download_report():
    lines, _ = analyze()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Line number", "Level", "Log message"])
    for number, line in enumerate(lines, start=1):
        kind = classify(line)
        writer.writerow([number, kind.upper(), line.rstrip("\n")])
    data = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    return send_file(
        data,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"log-analysis-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv",
    )

@app.errorhandler(413)
def file_too_large(_error):
    return "File too large. Please upload a file smaller than 2 MB.", 413

def payment_db():
    """Create a small local record of Paystack transactions."""
    with sqlite3.connect("payments.sqlite3") as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS payments (
            reference TEXT PRIMARY KEY, email TEXT NOT NULL, plan TEXT NOT NULL,
            amount_kobo INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
        )""")

@app.route("/pricing", methods=["GET"])
def pricing():
    return render_template_string(PRICING_HTML, message="", is_error=False)

@app.route("/paystack/initialize", methods=["POST"])
def paystack_initialize():
    secret = os.environ.get("PAYSTACK_SECRET_KEY", "").strip()
    if not secret:
        return render_template_string(PRICING_HTML, message="Payments are not configured yet. Please try again later.", is_error=True), 503
    email = request.form.get("email", "").strip().lower()
    plan = request.form.get("plan", "")
    if len(email) > 254 or "@" not in email or plan not in {"monthly", "yearly"}:
        return render_template_string(PRICING_HTML, message="Please enter a valid email and choose a plan.", is_error=True), 400
    # Amounts are in kobo. These are proposed prices and can be changed before launch.
    amount = {"monthly": 1_500_000, "yearly": 15_000_000}[plan]
    reference = "lap_" + secrets.token_urlsafe(18)
    payload = {"email": email, "amount": amount, "currency": "NGN", "reference": reference,
               "callback_url": request.url_root.rstrip("/") + "/paystack/callback",
               "metadata": {"custom_fields": [{"display_name": "Plan", "variable_name": "plan", "value": plan}]}}
    try:
        req = Request("https://api.paystack.co/transaction/initialize", data=json.dumps(payload).encode("utf-8"),
                      headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not result.get("status") or not result.get("data", {}).get("authorization_url"):
            raise ValueError("Paystack did not return a checkout URL")
        payment_db()
        with sqlite3.connect("payments.sqlite3") as conn:
            conn.execute("INSERT INTO payments(reference,email,plan,amount_kobo,status,created_at) VALUES(?,?,?,?,?,?)",
                         (reference, email, plan, amount, "pending", datetime.utcnow().isoformat()))
        return __import__("flask").redirect(result["data"]["authorization_url"])
    except (URLError, HTTPError, TimeoutError, ValueError, json.JSONDecodeError, OSError) as exc:
        app.logger.warning("Paystack initialization failed: %s", type(exc).__name__)
        return render_template_string(PRICING_HTML, message="We could not start checkout. Please try again later.", is_error=True), 502

@app.route("/paystack/callback", methods=["GET"])
def paystack_callback():
    secret = os.environ.get("PAYSTACK_SECRET_KEY", "").strip()
    reference = request.args.get("reference", "").strip()
    if not secret or not reference or len(reference) > 100:
        return render_template_string(PRICING_HTML, message="We could not verify this payment. Please contact support if you were charged.", is_error=True), 400
    try:
        req = Request("https://api.paystack.co/transaction/verify/" + reference,
                      headers={"Authorization": "Bearer " + secret}, method="GET")
        with urlopen(req, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
        data = result.get("data", {})
        payment_db()
        with sqlite3.connect("payments.sqlite3") as conn:
            row = conn.execute("SELECT email, plan, amount_kobo, status FROM payments WHERE reference=?", (reference,)).fetchone()
            if not row:
                return render_template_string(PRICING_HTML, message="This payment reference is not recognized by the site.", is_error=True), 400
            email, plan, expected_amount, old_status = row
            verified = (result.get("status") and data.get("status") == "success"
                        and data.get("reference") == reference and data.get("currency") == "NGN"
                        and data.get("amount") == expected_amount and str(data.get("customer", {}).get("email", "")).lower() == email)
            if not verified:
                conn.execute("UPDATE payments SET status=? WHERE reference=?", ("verification_failed", reference))
                return render_template_string(PRICING_HTML, message="Paystack could not confirm the expected successful payment. No Pro access has been granted.", is_error=True), 400
            conn.execute("UPDATE payments SET status=? WHERE reference=?", ("verified", reference))
        # This verifies and records payment only. Account login and durable Pro entitlement
        # are intentionally not claimed here; those must be added before selling Pro access.
        return render_template_string(PRICING_HTML, message="Payment verified successfully for " + email + ". Your payment is recorded, but Pro access is not activated yet. Please do not advertise this checkout as a finished subscription until account access and renewals are implemented.", is_error=False)
    except (URLError, HTTPError, TimeoutError, ValueError, json.JSONDecodeError, OSError) as exc:
        app.logger.warning("Paystack verification failed: %s", type(exc).__name__)
        return render_template_string(PRICING_HTML, message="We could not verify the payment right now. If you were charged, contact support before trying again.", is_error=True), 502

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
