import csv
import io
import os
import re
from datetime import datetime
from flask import Flask, request, render_template_string, redirect, url_for, flash, send_file

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

LEVELS = ("ERROR", "WARNING", "INFO", "DEBUG", "CRITICAL")
LOG_PATTERN = re.compile(
    r"(?i)\b(CRITICAL|ERROR|ERR|WARNING|WARN|INFO|DEBUG)\b"
)

BASE_STYLE = """
:root{--bg:#f4f7fb;--card:#fff;--ink:#182230;--muted:#657286;--line:#e3e9f2;--blue:#315efb;--blue2:#2448d8;--green:#12805c;--red:#c73535;--amber:#9a6200;--shadow:0 10px 28px rgba(27,45,78,.07)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif}
a{color:var(--blue);text-decoration:none}.wrap{max-width:1180px;margin:auto;padding:24px}
header{background:#101a2d;color:white}.nav{max-width:1180px;margin:auto;padding:18px 24px;display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap}
.brand{font-size:20px;font-weight:800;letter-spacing:.2px;color:white}.brand span{color:#89a4ff}.navlinks{display:flex;gap:18px;flex-wrap:wrap}.navlinks a{color:#d6def0;font-size:14px}
.hero{padding:32px 0 20px}.eyebrow{color:var(--blue);font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:1.3px}
h1{font-size:clamp(28px,4vw,42px);line-height:1.12;margin:8px 0 12px;letter-spacing:-1px}h2{font-size:20px;margin:0 0 12px}h3{font-size:16px;margin:0 0 8px}
.sub{color:var(--muted);max-width:720px;margin:0}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:22px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:var(--shadow);min-width:0}
.stat-label{color:var(--muted);font-size:13px}.stat-value{font-size:30px;font-weight:800;margin-top:5px}.stat-error{color:var(--red)}.stat-warning{color:var(--amber)}.stat-info{color:var(--green)}
.row{display:grid;grid-template-columns:1.1fr .9fr;gap:16px;align-items:start}.field{display:flex;flex-direction:column;gap:7px;margin:12px 0}
label{font-weight:700;font-size:13px}input[type=file],input[type=text],select,textarea{width:100%;padding:12px;border:1px solid #cfd8e6;border-radius:10px;background:white;color:var(--ink);font:inherit}
button,.btn{display:inline-flex;justify-content:center;align-items:center;gap:8px;border:0;border-radius:10px;padding:11px 15px;background:var(--blue);color:white;font-weight:750;font:inherit;cursor:pointer}
button:hover,.btn:hover{background:var(--blue2);color:white}.btn.secondary{background:#edf1ff;color:#2745b5}.btn.dark{background:#182230}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:12px}
.note{font-size:13px;color:var(--muted)}.flash{padding:12px 14px;border-radius:10px;margin:14px 0;background:#fff0f0;color:#982929;border:1px solid #ffd0d0}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.pill{font-size:12px;font-weight:800;border-radius:999px;padding:4px 9px;background:#edf1f7;color:#45536a}.pill.ERROR,.pill.CRITICAL{background:#ffe7e7;color:#a62626}.pill.WARNING{background:#fff1d2;color:#865600}.pill.INFO{background:#ddf7eb;color:#08734f}.pill.DEBUG{background:#e9edff;color:#354db1}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:#667287;font-size:12px;text-transform:uppercase;letter-spacing:.4px}td.message{min-width:280px;max-width:620px;overflow-wrap:anywhere;white-space:pre-wrap}
.empty{padding:30px;text-align:center;color:var(--muted)}.section{margin:18px 0}.explain{background:#f7f9ff;border:1px solid #e0e7ff;border-radius:12px;padding:13px;margin-top:8px}.explain strong{display:block;margin-bottom:4px}
footer{color:var(--muted);font-size:13px;padding:30px 24px;text-align:center}
@media(max-width:800px){.wrap{padding:16px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.row{grid-template-columns:1fr}.nav{padding:16px}.hero{padding-top:20px}.card{padding:16px}}
@media(max-width:420px){.grid{gap:9px}.stat-value{font-size:25px}.navlinks{gap:12px}.navlinks a{font-size:13px}}
@media print{header,.no-print,footer{display:none!important}body{background:white}.wrap{max-width:none;padding:0}.card{box-shadow:none;break-inside:avoid}.grid{grid-template-columns:repeat(4,1fr)}}
"""

LAYOUT = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} · Log Analyzer Pro</title><style>""" + BASE_STYLE + """</style></head><body>
<header><nav class="nav"><a class="brand" href="{{ url_for('index') }}">Log Analyzer <span>Pro</span></a>
<div class="navlinks"><a href="{{ url_for('index') }}">Dashboard</a><a href="{{ url_for('about') }}">About</a><a href="{{ url_for('contact') }}">Contact</a><a href="{{ url_for('privacy') }}">Privacy</a></div></nav></header>
<main class="wrap">{% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
{{ content|safe }}</main><footer>Log Analyzer Pro · Simple, practical log insights</footer></body></html>
"""

DASHBOARD = """
<section class="hero"><div class="eyebrow">Log monitoring made simple</div><h1>Understand your logs.<br>Find issues faster.</h1>
<p class="sub">Upload a .log or .txt file to count log levels, search messages, spot common problems, and export a report. Files are processed for this request and are not saved as a permanent log archive.</p></section>
<section class="row">
<div class="card"><h2>Upload a log file</h2><form method="post" enctype="multipart/form-data">
<div class="field"><label for="logfile">Choose a .log or .txt file (max 5 MB)</label><input id="logfile" type="file" name="logfile" accept=".log,.txt,text/plain" required></div>
<button type="submit">Analyze logs</button></form><p class="note">Tip: each line is checked for words such as ERROR, WARNING, INFO, DEBUG, and CRITICAL.</p></div>
<div class="card"><h2>What you get</h2><div class="pills"><span class="pill ERROR">Error detection</span><span class="pill WARNING">Warnings</span><span class="pill INFO">Info counts</span></div>
<p class="note">Filter results by keyword or severity, review plain-language suggestions, and download a CSV or printable report.</p></div></section>
"""

RESULTS = """
<section class="hero"><div class="eyebrow">Analysis complete</div><h1>{{ filename }}</h1><p class="sub">Found {{ total }} log lines. Use the filters to narrow down the results.</p></section>
<div class="grid">
<div class="card"><div class="stat-label">Total lines</div><div class="stat-value">{{ total }}</div></div>
<div class="card"><div class="stat-label">Errors / Critical</div><div class="stat-value stat-error">{{ counts.ERROR + counts.CRITICAL }}</div></div>
<div class="card"><div class="stat-label">Warnings</div><div class="stat-value stat-warning">{{ counts.WARNING }}</div></div>
<div class="card"><div class="stat-label">Info messages</div><div class="stat-value stat-info">{{ counts.INFO }}</div></div>
</div>
<div class="card section no-print"><h2>Filter log lines</h2><form method="get">
<div class="row"><div class="field"><label for="q">Search keyword</label><input id="q" name="q" type="text" value="{{ query }}" placeholder="e.g. database, timeout, failed"></div>
<div class="field"><label for="level">Severity</label><select id="level" name="level"><option value="ALL" {% if selected_level=='ALL' %}selected{% endif %}>All levels</option>{% for lvl in levels %}<option value="{{ lvl }}" {% if selected_level==lvl %}selected{% endif %}>{{ lvl }}</option>{% endfor %}<option value="OTHER" {% if selected_level=='OTHER' %}selected{% endif %}>Other / unclassified</option></select></div></div>
<div class="actions"><button type="submit">Apply filters</button><a class="btn secondary" href="{{ url_for('report', report_id=report_id) }}">Clear filters</a></div></form></div>
<div class="card section"><div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap"><h2>Log entries ({{ shown }} shown)</h2>
<div class="actions no-print"><a class="btn secondary" href="{{ url_for('download_csv', report_id=report_id) }}">Download CSV</a><a class="btn dark" href="{{ url_for('professional_report', report_id=report_id) }}">Professional report</a></div></div>
{% if entries %}<div class="table-wrap"><table><thead><tr><th>Line</th><th>Level</th><th>Message</th><th>Suggested next step</th></tr></thead><tbody>
{% for entry in entries %}<tr><td>{{ entry.number }}</td><td><span class="pill {{ entry.level }}">{{ entry.level }}</span></td><td class="message">{{ entry.message }}</td><td>{{ entry.advice }}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<div class="empty">No log lines match these filters.</div>{% endif %}</div>
"""

PRO_REPORT = """
<section class="hero"><div class="eyebrow">Log Analyzer Pro · Report</div><h1>Log Analysis Report</h1><p class="sub">File: {{ filename }} · Generated {{ generated }}</p></section>
<div class="grid"><div class="card"><div class="stat-label">Total lines</div><div class="stat-value">{{ total }}</div></div><div class="card"><div class="stat-label">Errors / Critical</div><div class="stat-value stat-error">{{ counts.ERROR + counts.CRITICAL }}</div></div><div class="card"><div class="stat-label">Warnings</div><div class="stat-value stat-warning">{{ counts.WARNING }}</div></div><div class="card"><div class="stat-label">Info</div><div class="stat-value stat-info">{{ counts.INFO }}</div></div></div>
<div class="card section"><h2>Summary and recommendations</h2>
{% if counts.ERROR + counts.CRITICAL %}<div class="explain"><strong>Priority: review errors first</strong>{{ counts.ERROR + counts.CRITICAL }} error or critical line(s) found. Check the timestamps and surrounding events, then inspect the affected service or component.</div>{% else %}<div class="explain"><strong>No explicit error levels detected</strong>No lines were classified as ERROR or CRITICAL. Review warnings and unclassified lines if you are investigating a problem.</div>{% endif %}
{% if counts.WARNING %}<div class="explain"><strong>Warnings need review</strong>{{ counts.WARNING }} warning line(s) found. Look for repeated warnings or patterns that occur before failures.</div>{% endif %}
{% if counts.DEBUG %}<div class="explain"><strong>Debug output present</strong>{{ counts.DEBUG }} debug line(s) found. Debug logs can help with investigation but may be noisy in production.</div>{% endif %}
<p class="note">This report is an automated first-pass review, not a guarantee that every issue has been identified.</p></div>
<div class="card section"><h2>Log entries</h2><div class="table-wrap"><table><thead><tr><th>Line</th><th>Level</th><th>Message</th><th>Suggested next step</th></tr></thead><tbody>{% for entry in entries %}<tr><td>{{ entry.number }}</td><td><span class="pill {{ entry.level }}">{{ entry.level }}</span></td><td class="message">{{ entry.message }}</td><td>{{ entry.advice }}</td></tr>{% endfor %}</tbody></table></div></div>
<div class="actions no-print"><button onclick="window.print()">Print / Save as PDF</button><a class="btn secondary" href="{{ url_for('report', report_id=report_id) }}">Back to dashboard</a><a class="btn secondary" href="{{ url_for('download_csv', report_id=report_id) }}">Download CSV</a></div>
"""

PAGE = """
<section class="hero"><div class="eyebrow">Log Analyzer Pro</div><h1>{{ heading }}</h1><p class="sub">{{ intro }}</p></section>
<div class="card">{{ body|safe }}</div>
"""

# In-memory reports are short-lived and may be cleared whenever the server restarts.
REPORTS = {}
MAX_LINES_IN_REPORT = 10000

def classify(line):
    match = LOG_PATTERN.search(line)
    if not match:
        return "OTHER"
    raw = match.group(1).upper()
    if raw in ("ERR",):
        return "ERROR"
    if raw == "WARN":
        return "WARNING"
    return raw

def advice_for(level, message):
    lower = message.lower()
    if level in ("ERROR", "CRITICAL"):
        if any(word in lower for word in ("timeout", "timed out", "deadline")):
            return "Check service response time, network connectivity, and timeout settings."
        if any(word in lower for word in ("permission", "denied", "forbidden", "unauthorized")):
            return "Verify account permissions, credentials, and access rules."
        if any(word in lower for word in ("database", "sql", "connection refused", "connection failed")):
            return "Check database availability, connection settings, and service logs."
        if any(word in lower for word in ("memory", "out of memory", "oom")):
            return "Review memory usage, resource limits, and recent workload changes."
        if any(word in lower for word in ("not found", "no such file", "missing")):
            return "Confirm the file, path, or requested resource exists and is configured correctly."
        return "Inspect nearby log lines and the affected component; reproduce the issue if possible."
    if level == "WARNING":
        return "Check whether this repeats and whether it appears before an error."
    if level == "INFO":
        return "Informational event; compare its timestamp with any reported issue."
    if level == "DEBUG":
        return "Useful for troubleshooting; avoid excessive debug output in production."
    return "Review this line if it relates to the issue you are investigating."

def analyze_text(text_value, filename):
    raw_lines = text_value.splitlines()
    if len(raw_lines) > MAX_LINES_IN_REPORT:
        raw_lines = raw_lines[:MAX_LINES_IN_REPORT]
    entries = []
    counts = {level: 0 for level in LEVELS}
    for number, line in enumerate(raw_lines, start=1):
        level = classify(line)
        if level in counts:
            counts[level] += 1
        entries.append({
            "number": number,
            "level": level,
            "message": line,
            "advice": advice_for(level, line)
        })
    report_id = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    REPORTS[report_id] = {
        "filename": filename,
        "entries": entries,
        "counts": counts,
        "total": len(entries),
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    }
    # Keep memory use bounded.
    while len(REPORTS) > 8:
        REPORTS.pop(next(iter(REPORTS)))
    return report_id

def get_report(report_id):
    return REPORTS.get(report_id)

@app.errorhandler(413)
def too_large(_error):
    flash("That file is too large. Please upload a file smaller than 5 MB.")
    return redirect(url_for("index"))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        uploaded = request.files.get("logfile")
        if not uploaded or not uploaded.filename:
            flash("Choose a .log or .txt file first.")
            return redirect(url_for("index"))
        filename = os.path.basename(uploaded.filename)
        if not filename.lower().endswith((".log", ".txt")):
            flash("Please upload a file ending in .log or .txt.")
            return redirect(url_for("index"))
        try:
            content = uploaded.read().decode("utf-8", errors="replace")
        except Exception:
            flash("The file could not be read. Please try a plain-text log file.")
            return redirect(url_for("index"))
        report_id = analyze_text(content, filename)
        return redirect(url_for("report", report_id=report_id))
    return render_template_string(LAYOUT, title="Dashboard", content=render_template_string(DASHBOARD))

@app.route("/report/<report_id>")
def report(report_id):
    data = get_report(report_id)
    if not data:
        flash("This report has expired or the server restarted. Upload the log file again.")
        return redirect(url_for("index"))
    query = request.args.get("q", "").strip().lower()
    selected_level = request.args.get("level", "ALL").upper()
    valid_levels = list(LEVELS) + ["OTHER"]
    if selected_level not in ["ALL"] + valid_levels:
        selected_level = "ALL"
    filtered = [
        e for e in data["entries"]
        if (not query or query in e["message"].lower())
        and (selected_level == "ALL" or e["level"] == selected_level)
    ]
    content = render_template_string(
        RESULTS, filename=data["filename"], total=data["total"], counts=data["counts"],
        entries=filtered[:2000], shown=min(len(filtered), 2000), query=request.args.get("q", ""),
        selected_level=selected_level, levels=LEVELS, report_id=report_id
    )
    return render_template_string(LAYOUT, title="Analysis", content=content)

@app.route("/report/<report_id>/professional")
def professional_report(report_id):
    data = get_report(report_id)
    if not data:
        flash("This report has expired or the server restarted. Upload the log file again.")
        return redirect(url_for("index"))
    content = render_template_string(PRO_REPORT, filename=data["filename"], generated=data["generated"],
        total=data["total"], counts=data["counts"], entries=data["entries"][:2000], report_id=report_id)
    return render_template_string(LAYOUT, title="Professional Report", content=content)

@app.route("/report/<report_id>/csv")
def download_csv(report_id):
    data = get_report(report_id)
    if not data:
        flash("This report has expired or the server restarted. Upload the log file again.")
        return redirect(url_for("index"))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Line", "Level", "Message", "Suggested next step"])
    for entry in data["entries"]:
        writer.writerow([entry["number"], entry["level"], entry["message"], entry["advice"]])
    binary = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    binary.seek(0)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(data["filename"])[0]) or "log"
    return send_file(binary, mimetype="text/csv", as_attachment=True, download_name=f"{safe_name}_report.csv")

@app.route("/about")
def about():
    body = "<h2>What this tool does</h2><p>Log Analyzer Pro reads a plain-text log file and identifies common severity labels, counts events, filters messages, and exports a report.</p><h2>How to use it</h2><ol><li>Choose a .log or .txt file.</li><li>Tap <b>Analyze logs</b>.</li><li>Search by keyword or filter by severity.</li><li>Download the CSV or open the printable report.</li></ol><p class='note'>The tool offers suggestions based on message text. Always verify findings against your application and infrastructure.</p>"
    return render_template_string(LAYOUT, title="About", content=render_template_string(PAGE, heading="About Log Analyzer Pro", intro="A straightforward helper for reviewing plain-text application logs.", body=body))

@app.route("/contact")
def contact():
    body = "<p>For help or feedback, contact the website owner using the email address or contact method provided by the owner of this service.</p><p class='note'>A contact email has not been configured on this demo page. Add your preferred public contact details before promoting the site.</p>"
    return render_template_string(LAYOUT, title="Contact", content=render_template_string(PAGE, heading="Contact", intro="Questions, feedback, or suggestions.", body=body))

@app.route("/privacy")
def privacy():
    body = "<h2>File handling</h2><p>Uploaded log contents are processed in server memory for analysis. This app does not intentionally write uploaded log files to permanent storage. Reports are held temporarily in server memory and may disappear when the server restarts or when the service replaces older reports.</p><h2>Be careful with sensitive data</h2><p>Logs can contain passwords, tokens, personal information, IP addresses, or other secrets. Remove sensitive data before uploading. This simple app does not pro
