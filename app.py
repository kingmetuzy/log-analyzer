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
    <span class="badge">FLASK • LEVEL 5 PROJECT</span>
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
        {% if item.explanation %}<div class="explanation"><strong>Possible meaning:</strong> {{ item.explanation }}<br><strong>Suggested check:</strong> {{ item.action }}</div>{% endif %}
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
