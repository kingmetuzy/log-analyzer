from flask import Flask, request, render_template_string, send_file
from collections import Counter
from werkzeug.utils import secure_filename
import os
import io
import re
import csv
from datetime import datetime

app = Flask(__name__)
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
    :root { color-scheme: dark; --bg:#080d1a; --panel:#111a2d; --muted:#a6b2cc; --text:#f4f7ff; --line:#293752; --blue:#76a9ff; }
    * { box-sizing:border-box; }
    body { margin:0; background:radial-gradient(ellipse at top,#142342 0%,var(--bg) 48%); color:var(--text); font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif; }
    .wrap { max-width:1120px; margin:auto; padding:26px 18px 44px; }
    header { display:flex; justify-content:space-between; gap:16px; align-items:center; flex-wrap:wrap; margin-bottom:16px; }
    h1 { margin:0; font-size:clamp(25px,5vw,36px); letter-spacing:-.7px; }
    .sub { color:var(--muted); margin:5px 0 0; }
    .badge { background:#20345c; color:#c5dcff; border:1px solid #35548b; padding:7px 11px; border-radius:999px; font-size:12px; font-weight:700; }
    .nav { display:flex; flex-wrap:wrap; gap:8px; margin:14px 0 20px; }
    .nav a { color:#c9d9ff; text-decoration:none; border:1px solid var(--line); border-radius:999px; padding:7px 12px; font-size:13px; }
    .nav a:hover { background:#1c2b49; }
    .hero { padding:24px; border:1px solid #344b75; border-radius:18px; background:linear-gradient(125deg,#172a4b,#111a2d 68%); box-shadow:0 16px 40px #0002; }
    .hero h2 { font-size:clamp(21px,4vw,29px); margin:0 0 8px; letter-spacing:-.4px; }
    .hero p { margin:0; max-width:720px; color:#c0cce3; }
    .cards { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:18px 0; }
    .card,.panel { background:linear-gradient(145deg,#141e34,var(--panel)); border:1px solid var(--line); border-radius:15px; padding:17px; box-shadow:0 8px 24px #00000012; }
    .label { color:var(--muted); font-size:13px; }
    .num { font-size:29px; font-weight:800; margin-top:4px; overflow-wrap:anywhere; letter-spacing:-.5px; }
    .panel { margin-top:15px; }
    h2 { font-size:18px; margin:0 0 12px; }
    form { margin:0; }
    .row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
    input,select,button,.button { border:1px solid var(--line); border-radius:9px; padding:10px 12px; font:inherit; }
    input,select { background:#0c1427; color:var(--text); max-width:100%; }
    input[type=file] { width:100%; }
    button,.button { background:linear-gradient(135deg,#3478e5,#2458b8); color:white; border:0; cursor:pointer; text-decoration:none; display:inline-block; font-weight:650; box-shadow:0 5px 14px #1d4b9926; }
    button:hover,.button:hover { filter:brightness(1.12); transform:translateY(-1px); }
    input:focus,select:focus,button:focus,.button:focus { outline:2px solid var(--blue); outline-offset:2px; }
    .secondary { background:#34415b; }
    .notice { padding:11px 13px; border-radius:10px; margin:12px 0; background:#152d2a; border:1px solid #28685c; }
    .error-notice { background:#3a2029; border-color:#814052; }
    .muted { color:var(--muted); }
    .log { border:1px solid var(--line); border-left:4px solid #5a6c8f; border-radius:8px; padding:11px 12px; margin:8px 0; overflow-wrap:anywhere; white-space:pre-wrap; }
    .log.error { border-left-color:#ff667e; background:#2b1824; }
    .log.warning { border-left-color:#ffc857; background:#302919; }
    .log.info { border-left-color:#4bd4a3; background:#142b29; }
    .log.other { border-left-color:#7f8aa7; background:#1b2336; }
    .explanation { margin:8px 0 14px; padding:10px 12px; border:1px solid #35548b; border-radius:8px; background:#14213a; color:#dce8ff; }
    .empty { padding:20px; text-align:center; color:var(--muted); border:1px dashed var(--line); border-radius:10px; }
    .footer { text-align:center; color:var(--muted); margin-top:24px; font-size:13px; }
    @media(max-width:650px) { .cards { grid-template-columns:repeat(2,minmax(0,1fr)); } .wrap { padding:18px 12px 30px; } .num { font-size:24px; } }
  </style>
</head>
<body>
<div class="wrap">
  <header>
    <div><h1>📊 Log Analyzer Pro</h1><p class="sub">Upload, search, and summarize application logs.</p></div>
    <span class="badge">LOG ANALYSIS WORKSPACE</span>
  </header>
  <nav class="nav" aria-label="Main navigation"><a href="/">Dashboard</a><a href="/about">About</a><a href="/contact">Contact</a><a href="/privacy">Privacy</a></nav>
  <section class="hero"><h2>Understand your logs. Find issues faster.</h2><p>Upload a text log, spot errors and warnings, search important events, and export a clean report. Your analysis is designed to be simple on desktop and mobile.</p></section>

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
      <a class="button" href="/report.html" target="_blank">Professional report</a>
      <a class="button" href="/report.csv">Download CSV report</a>
    </div>
    <p class="muted">Showing {{ shown }} of {{ stats.total }} lines. Counts are based on the loaded log file.</p>
    {% if logs %}
      {% for item in logs %}
        <div class="log {{ item.kind }}">{{ item.text }}</div>
        {% if item.explanation %}<div class="explanation"><strong>Possible meaning:</strong> {{ item.explanation }}<br><strong>Suggested check:</strong> {{ item.action }}</div>{% endif %}
      {% endfor %}
    {% else %}
      <div class="empty">No log lines match these filters.</div>
    {% endif %}
  </section>
  <div class="footer">Log Analyzer Pro • Clear insights from application logs • Analyze only logs you are authorized to access.<br><span><a href="/about" style="color:inherit">About</a> · <a href="/contact" style="color:inherit">Contact</a> · <a href="/privacy" style="color:inherit">Privacy</a></span></div>
</div>
</body>
</html>
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

def explain_error(line):
    """Give cautious, rule-based guidance for common log messages."""
    text = line.lower()
    rules = [
        (("database", "db connection", "connection refused", "could not connect"),
         "A service connection may have been refused or the database may be unavailable.",
         "Check the database service, host/port settings, network access, and credentials."),
        (("timeout", "timed out", "deadline exceeded"),
         "An operation took longer than the allowed time.",
         "Check service health, network latency, and timeout settings."),
        (("dns", "name resolution", "could not resolve host", "getaddrinfo failed"),
         "The application may be unable to resolve a server name to an address.",
         "Check the hostname, DNS settings, and network connection."),
        (("connection reset", "connection aborted", "broken pipe", "network is unreachable", "no route to host"),
         "A network connection may have been interrupted or the destination may be unreachable.",
         "Check network access, the destination service, firewall rules, and whether the connection is being closed unexpectedly."),
        (("ssl", "tls", "certificate verify failed", "certificate has expired"),
         "A secure connection may have failed because of a TLS or certificate problem.",
         "Check the certificate validity, hostname match, certificate chain, and system clock. Do not disable certificate checks as a shortcut."),
        (("permission denied", "access denied", "forbidden", "operation not permitted"),
         "The process may not have permission to access a file or resource.",
         "Check the account permissions, ownership, and resource access rules."),
        (("out of memory", "memory error", "memoryerror", "high memory", "oomkilled", "oom kill"),
         "The application may be running low on available memory.",
         "Check memory usage, recent workload changes, and whether the process is handling unusually large data."),
        (("no space left", "disk full", "out of disk space"),
         "The system may have run out of storage space.",
         "Check available disk space and log-file growth; remove only files you are sure are safe to delete."),
        (("file not found", "no such file", "filenotfounderror", "cannot find the path"),
         "A required file or path may be missing or incorrect.",
         "Check the file path, filename spelling, and whether the file exists in the expected environment."),
        (("login failed", "failed login", "login failure", "authentication failed", "invalid password", "unknown user", "user not found"),
         "A sign-in attempt was rejected. The log alone does not show whether the username, password, account status, or login policy caused it.",
         "Check the username and account status, review authentication logs for the specific reason, and confirm login settings. Never store or share passwords in logs."),
        (("unauthorized", "invalid token", "token expired", "authentication required"),
         "The request may have been rejected because authentication was missing, invalid, or expired.",
         "Check that the user is signed in and that any token is valid and not expired. Never paste secrets into shared logs."),
        (("too many requests", "rate limit", "http 429", "status code 429"),
         "The service may be limiting requests because too many arrived in a short period.",
         "Check the service's rate limits, reduce request frequency, and follow any Retry-After guidance."),
        (("404", "not found"),
         "The requested page, route, or resource may not exist at that address.",
         "Check the URL, route configuration, and whether the resource is available. Confirm this is an actual 404 status and not just text containing 'not found'."),
        (("500 internal server error", "http 500", "status code 500"),
         "The server encountered an unexpected problem while handling a request.",
         "Review the server logs around the same timestamp and check recent code or configuration changes."),
        (("module not found", "modulenotfounderror", "importerror", "no module named"),
         "A required code module may be missing or unavailable in the environment.",
         "Check the dependency list and deployment environment, and install the required package if appropriate."),
        (("syntaxerror", "syntax error"),
         "The program may contain code that cannot be parsed.",
         "Check the file and line number reported by the runtime for missing punctuation or invalid syntax."),
    ]
    for phrases, meaning, action in rules:
        if any(phrase in text for phrase in phrases):
            return meaning, action
    return (
        "This line is marked as an error, but its exact cause cannot be determined from the text alone.",
        "Review nearby log lines, timestamps, and the relevant service or application documentation."
    )
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
            item = {"text": line.rstrip("\n"), "kind": kind}
            if kind == "error":
                item["explanation"], item["action"] = explain_error(line)
            filtered.append(item)

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


@app.route("/report.html", methods=["GET"])
def professional_report():
    lines, stats = analyze()
    created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entries = []
    for number, line in enumerate(lines, start=1):
        text = line.rstrip("\n")
        kind = classify(text)
        meaning, action = explain_error(text) if kind == "error" else ("", "")
        entries.append({
            "number": number,
            "level": kind.upper(),
            "text": text,
            "meaning": meaning,
            "action": action,
        })

    report_html = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log Analyzer Pro — Professional Report</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#eef2f8;color:#182238;font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:950px;margin:28px auto;padding:28px;background:white;border:1px solid #d8deea;border-radius:14px}
header{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap;border-bottom:2px solid #d8deea;padding-bottom:18px}
h1{margin:0;font-size:28px}h2{font-size:18px;margin:22px 0 10px}.muted{color:#5c6880}
.actions{display:flex;gap:8px;flex-wrap:wrap}button,a.btn{border:0;border-radius:8px;padding:10px 14px;background:#245ec7;color:white;text-decoration:none;font:inherit;cursor:pointer}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:18px 0}
.card{background:#f5f7fb;border:1px solid #d8deea;border-radius:10px;padding:14px}.label{font-size:13px;color:#5c6880}.num{font-size:26px;font-weight:750}
table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{text-align:left;padding:10px;border-bottom:1px solid #d8deea;vertical-align:top;overflow-wrap:anywhere}th{background:#f5f7fb}
.level{font-weight:700}.ERROR{color:#b4233a}.WARNING{color:#936200}.INFO{color:#087d5d}.OTHER{color:#5c6880}
.explain{margin-top:6px;background:#f1f5ff;border-left:3px solid #5379c7;padding:8px 10px;border-radius:5px;font-size:13px}
footer{margin-top:24px;padding-top:14px;border-top:1px solid #d8deea;font-size:12px;color:#5c6880}
@media(max-width:600px){main{margin:0;padding:16px;border-radius:0}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}table{font-size:13px}th,td{padding:7px}}
@media print{body{background:white}main{max-width:none;margin:0;padding:0;border:0}.actions{display:none}.card{break-inside:avoid}tr{break-inside:avoid}}
</style>
</head>
<body><main>
<header><div><h1>Log Analyzer Pro</h1><p class="muted">Professional Log Analysis Report</p><p class="muted">Generated: {{ created }}</p></div>
<div class="actions"><button onclick="window.print()">Print / Save as PDF</button><a class="btn" href="/">Back to dashboard</a></div></header>
<section class="cards">
<div class="card"><div class="label">Total lines</div><div class="num">{{ stats.total }}</div></div>
<div class="card"><div class="label">Errors</div><div class="num">{{ stats.errors }}</div></div>
<div class="card"><div class="label">Warnings</div><div class="num">{{ stats.warnings }}</div></div>
<div class="card"><div class="label">Info / other</div><div class="num">{{ stats.info_other }}</div></div>
</section>
<h2>Summary</h2><p>The report reviewed {{ stats.total }} log lines, identifying {{ stats.errors }} error(s), {{ stats.warnings }} warning(s), and {{ stats.info_other }} informational or uncategorized line(s).</p>
<h2>Log details</h2>
<table><thead><tr><th style="width:7%">#</th><th style="width:12%">Level</th><th>Log message and guidance</th></tr></thead><tbody>
{% for item in entries %}<tr><
