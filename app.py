import csv
import io
import os
import re
from datetime import datetime
from flask import Flask, request, render_template_string, redirect, url_for, flash, send_file

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "log-analyzer-pro-change-this-key")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

LEVELS = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]
PATTERN = re.compile(r"\b(CRITICAL|ERROR|ERR|WARNING|WARN|INFO|DEBUG)\b", re.I)
REPORTS = {}

STYLE = """
:root{--bg:#f4f7ff;--card:#fff;--ink:#14213d;--muted:#63718b;--line:#e0e8f5;--blue:#2457e6;--blue2:#1239a8;--pale:#eaf0ff;--red:#b42332;--amber:#946200;--green:#08784f}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:radial-gradient(ellipse at top left,#e8efff 0,transparent 38%),var(--bg);color:var(--ink);font:15px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Arial,sans-serif}
header{background:linear-gradient(115deg,#10245b,#173eaa 58%,#2457e6);color:#fff;box-shadow:0 8px 28px #10245b24}
.nav{max-width:1160px;margin:auto;padding:17px 24px;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.brand{font-size:21px;font-weight:850;letter-spacing:-.5px;color:#fff;text-decoration:none}.brand span{color:#b9ccff}
.links{display:flex;gap:8px;flex-wrap:wrap}.links a{color:#e3eaff;text-decoration:none;font-size:14px;font-weight:650;padding:8px 11px;border-radius:9px;transition:background .2s}.links a:hover{background:#ffffff20;color:#fff}
main{max-width:1160px;margin:auto;padding:30px 24px 36px}
.hero{padding:28px 0 22px}.eyebrow{display:inline-flex;align-items:center;gap:8px;font-size:12px;letter-spacing:1.2px;text-transform:uppercase;color:var(--blue);font-weight:850}.eyebrow:before{content:"";display:inline-block;width:20px;height:3px;border-radius:3px;background:var(--blue)}
h1{font-size:clamp(30px,5vw,48px);line-height:1.12;letter-spacing:-1.6px;margin:10px 0 14px;font-weight:850}h2{font-size:20px;letter-spacing:-.35px;margin:0 0 12px}.sub,.muted{color:var(--muted)}.sub{max-width:740px;font-size:16px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin:20px 0}
.card{background:var(--card);border:1px solid #e2e9f6;border-radius:18px;padding:22px;margin:15px 0;box-shadow:0 12px 34px #163c7c0a;min-width:0}
.grid .card{margin:0;position:relative;overflow:hidden}.grid .card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:#b9caff}.grid .card:nth-child(2):before{background:#e05a68}.grid .card:nth-child(3):before{background:#e9b949}.grid .card:nth-child(4):before{background:#2bb889}
.stat-label{font-size:12px;color:var(--muted);font-weight:750;text-transform:uppercase;letter-spacing:.6px}.stat-value{font-size:34px;line-height:1.25;font-weight:850;letter-spacing:-1px;margin-top:7px}.error{color:var(--red)}.warning{color:var(--amber)}.info{color:var(--green)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:stretch}.field{margin:14px 0}.field label{display:block;font-weight:750;font-size:13px;margin-bottom:7px}
input[type=file],input[type=text],select{width:100%;padding:13px 14px;border:1px solid #cbd7ec;border-radius:11px;background:#fff;color:var(--ink);font:inherit;outline:none;transition:border .2s,box-shadow .2s}
input[type=file]:focus,input[type=text]:focus,select:focus{border-color:var(--blue);box-shadow:0 0 0 4px #2457e617}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 17px;border:1px solid transparent;border-radius:11px;background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;font:inherit;font-weight:800;text-decoration:none;cursor:pointer;box-shadow:0 6px 15px #2457e626;transition:transform .15s,box-shadow .15s}
button:hover,.btn:hover{transform:translateY(-1px);box-shadow:0 9px 20px #2457e632}.btn.secondary{background:var(--pale);color:#2148b9;box-shadow:none;border-color:#d7e2ff}.btn.dark{background:#182747;color:#fff;box-shadow:none}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin:15px 0}.note{font-size:13px;color:var(--muted)}.flash{background:#fff1f2;color:#922b32;border:1px solid #ffd0d4;border-radius:12px;padding:13px 15px;margin:12px 0}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;font-size:13px;background:#fff}th,td{text-align:left;padding:12px 13px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;color:#596984;text-transform:uppercase;letter-spacing:.65px;background:#f7f9fe}tbody tr:hover{background:#f8faff}td.message{min-width:260px;max-width:600px;white-space:pre-wrap;overflow-wrap:anywhere}
.badge{display:inline-block;border-radius:99px;background:#e9edf5;padding:4px 9px;font-size:11px;font-weight:850;letter-spacing:.3px}.badge.ERROR,.badge.CRITICAL{background:#ffe6e7;color:#a3222c}.badge.WARNING{background:#fff0cb;color:#825700}.badge.INFO{background:#dff7eb;color:#08734e}.badge.DEBUG{background:#e7eaff;color:#344ab0}
.tip{background:#f3f6ff;border:1px solid #dce6ff;border-radius:12px;padding:13px 15px;margin:10px 0}.empty{text-align:center;padding:28px;color:var(--muted)}footer{text-align:center;color:var(--muted);font-size:13px;padding:28px 18px;border-top:1px solid #e5ebf6;background:#fff}
@media(max-width:760px){main{padding:18px 14px 28px}.hero{padding:20px 0 12px}.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}.row{grid-template-columns:1fr;gap:4px}.card{padding:17px;border-radius:15px}.nav{padding:14px 16px}.links{gap:3px}.links a{padding:7px 8px}.stat-value{font-size:29px}}
@media(max-width:400px){.stat-value{font-size:25px}.links a{font-size:12px}h1{letter-spacing:-.8px}}
@media print{header,footer,.no-print{display:none!important}body{background:#fff}main{padding:0;max-width:none}.card{box-shadow:none;break-inside:avoid;border-color:#ddd}}
"""

LAYOUT = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} | Log Analyzer Pro</title><style>""" + STYLE + """</style></head><body>
<header><nav class="nav"><a class="brand" href="/">Log Analyzer <span>Pro</span></a>
<div class="links"><a href="/">Dashboard</a><a href="/about">About</a><a href="/contact">Contact</a><a href="/privacy">Privacy</a></div></nav></header>
<main>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}{{ content|safe }}</main>
<footer>Log Analyzer Pro · Practical log insights</footer></body></html>
"""

HOME = """
<section class="hero"><div class="eyebrow">Clearer logs · Faster troubleshooting</div><h1>Find the signal<br>inside your logs.</h1>
<p class="sub">Upload a plain-text log file to count severity levels, search messages, review suggestions, and export a report.</p></section>
<div class="row"><section class="card"><h2>Start a log analysis</h2><p class="muted">Upload a log and get a quick, readable overview.</p><form method="post" enctype="multipart/form-data">
<div class="field"><label for="logfile">Choose a .log or .txt file (maximum 5 MB)</label><input id="logfile" type="file" name="logfile" accept=".log,.txt,text/plain" required></div><button type="submit">Analyze logs</button></form>
<p class="note">Supported labels include ERROR, CRITICAL, WARNING, INFO, and DEBUG.</p></section>
<section class="card"><h2>Features</h2><p>✓ Error and warning counts</p><p>✓ Search and severity filters</p><p>✓ Smart next-step suggestions</p><p>✓ CSV export and printable reports</p></section></div>
"""

RESULTS = """
<section class="hero"><div class="eyebrow">Analysis complete</div><h1>{{ filename }}</h1><p class="sub">{{ total }} lines analyzed.</p></section>
<div class="grid">
<div class="card"><div class="stat-label">Total lines</div><div class="stat-value">{{ total }}</div></div>
<div class="card"><div class="stat-label">Errors / Critical</div><div class="stat-value error">{{ counts.ERROR + counts.CRITICAL }}</div></div>
<div class="card"><div class="stat-label">Warnings</div><div class="stat-value warning">{{ counts.WARNING }}</div></div>
<div class="card"><div class="stat-label">Info</div><div class="stat-value info">{{ counts.INFO }}</div></div></div>
<div class="card no-print"><h2>Filter results</h2><form method="get"><div class="row">
<div class="field"><label for="q">Search keyword</label><input id="q" name="q" type="text" value="{{ query }}" placeholder="database, timeout, failed..."></div>
<div class="field"><label for="level">Severity</label><select id="level" name="level"><option value="ALL">All levels</option>{% for l in levels %}<option value="{{ l }}" {% if selected==l %}selected{% endif %}>{{ l }}</option>{% endfor %}<option value="OTHER" {% if selected=="OTHER" %}selected{% endif %}>Other</option></select></div></div>
<div class="actions"><button type="submit">Apply filters</button><a class="btn secondary" href="{{ url_for('report', report_id=rid) }}">Clear filters</a></div></form></div>
<div class="card"><div class="actions no-print"><h2 style="margin-right:auto">Log entries ({{ shown }} shown)</h2><a class="btn secondary" href="{{ url_for('csv_report', report_id=rid) }}">Download CSV</a><a class="btn dark" href="{{ url_for('pro_report', report_id=rid) }}">Professional report</a></div>
{% if entries %}<div class="table-wrap"><table><thead><tr><th>Line</th><th>Level</th><th>Message</th><th>Suggested next step</th></tr></thead><tbody>
{% for e in entries %}<tr><td>{{ e.number }}</td><td><span class="badge {{ e.level }}">{{ e.level }}</span></td><td class="message">{{ e.message }}</td><td>{{ e.advice }}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<div class="empty">No matching lines.</div>{% endif %}</div>
"""

PRO = """
<section class="hero"><div class="eyebrow">Log Analyzer Pro · Report</div><h1>Log Analysis Report</h1><p class="sub">File: {{ filename }} · Generated {{ generated }}</p></section>
<div class="grid"><div class="card"><div class="stat-label">Total lines</div><div class="stat-value">{{ total }}</div></div><div class="card"><div class="stat-label">Errors / Critical</div><div class="stat-value error">{{ counts.ERROR + counts.CRITICAL }}</div></div><div class="card"><div class="stat-label">Warnings</div><div class="stat-value warning">{{ counts.WARNING }}</div></div><div class="card"><div class="stat-label">Info</div><div class="stat-value info">{{ counts.INFO }}</div></div></div>
<div class="card"><h2>Summary and suggestions</h2>
{% if counts.ERROR + counts.CRITICAL %}<div class="tip"><b>Review errors first</b><br>{{ counts.ERROR + counts.CRITICAL }} error or critical line(s) found. Inspect nearby lines and the affected service.</div>{% else %}<div class="tip"><b>No explicit error levels detected</b><br>Review warnings and unclassified lines if you are investigating an issue.</div>{% endif %}
{% if counts.WARNING %}<div class="tip"><b>Warnings found</b><br>{{ counts.WARNING }} warning line(s) found. Check whether they repeat or occur before errors.</div>{% endif %}
<p class="note">Automated suggestions are a starting point; verify them against your application.</p></div>
<div class="card"><h2>Log entries</h2><div class="table-wrap"><table><thead><tr><th>Line</th><th>Level</th><th>Message</th><th>Suggested next step</th></tr></thead><tbody>{% for e in entries %}<tr><td>{{ e.number }}</td><td><span class="badge {{ e.level }}">{{ e.level }}</span></td><td class="message">{{ e.message }}</td><td>{{ e.advice }}</td></tr>{% endfor %}</tbody></table></div></div>
<div class="actions no-print"><button onclick="window.print()">Print / Save as PDF</button><a class="btn secondary" href="{{ url_for('report', report_id=rid) }}">Back to results</a><a class="btn secondary" href="{{ url_for('csv_report', report_id=rid) }}">Download CSV</a></div>
"""

def classify(line):
    match = PATTERN.search(line)
    if not match:
        return "OTHER"
    level = match.group(1).upper()
    if level == "ERR":
        return "ERROR"
    if level == "WARN":
        return "WARNING"
    return level

def suggestion(level, line):
    lower = line.lower()
    if level in ("ERROR", "CRITICAL"):
        if "timeout" in lower or "timed out" in lower:
            return "Check service response time, network connectivity, and timeout settings."
        if any(x in lower for x in ("permission", "denied", "unauthorized", "forbidden")):
            return "Check credentials, permissions, and access rules."
        if any(x in lower for x in ("database", "sql", "connection refused")):
            return "Check database availability and connection settings."
        if any(x in lower for x in ("memory", "out of memory", "oom")):
            return "Review memory usage and resource limits."
        return "Inspect nearby log lines and the affected component."
    if level == "WARNING":
        return "Check whether this repeats or appears before an error."
    if level == "INFO":
        return "Informational event; compare its time with the issue."
    if level == "DEBUG":
        return "Useful for troubleshooting; avoid excessive debug output in production."
    return "Review this line if it relates to the issue you are investigating."

def make_report(text, filename):
    lines = text.splitlines()[:10000]
    counts = {level: 0 for level in LEVELS}
    entries = []
    for number, line in enumerate(lines, 1):
        level = classify(line)
        if level in counts:
            counts[level] += 1
        entries.append({"number": number, "level": level, "message": line, "advice": suggestion(level, line)})
    rid = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    REPORTS[rid] = {"filename": filename, "counts": counts, "entries": entries, "total": len(entries),
                    "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
    while len(REPORTS) > 8:
        REPORTS.pop(next(iter(REPORTS)))
    return rid

def layout(title, content):
    return render_template_string(LAYOUT, title=title, content=content)

@app.errorhandler(413)
def too_large(_error):
    flash("File too large. Please upload a file smaller than 5 MB.")
    return redirect(url_for("index"))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files.get("logfile")
        if not file or not file.filename:
            flash("Choose a log file first.")
            return redirect(url_for("index"))
        filename = os.path.basename(file.filename)
        if not filename.lower().endswith((".log", ".txt")):
            flash("Please choose a .log or .txt file.")
            return redirect(url_for("index"))
        text = file.read().decode("utf-8", errors="replace")
        rid = make_report(text, filename)
        return redirect(url_for("report", report_id=rid))
    return layout("Dashboard", render_template_string(HOME))

@app.route("/report/<report_id>")
def report(report_id):
    data = REPORTS.get(report_id)
    if not data:
        flash("Report expired or server restarted. Please upload the file again.")
        return redirect(url_for("index"))
    query = request.args.get("q", "").strip().lower()
    selected = request.args.get("level", "ALL").upper()
    allowed = LEVELS + ["OTHER"]
    if selected not in ["ALL"] + allowed:
        selected = "ALL"
    entries = [e for e in data["entries"] if (not query or query in e["message"].lower()) and (selected == "ALL" or e["level"] == selected)]
    content = render_template_string(RESULTS, filename=data["filename"], total=data["total"], counts=data["counts"],
        entries=entries[:2000], shown=min(len(entries), 2000), query=request.args.get("q", ""), selected=selected,
        levels=LEVELS, rid=report_id)
    return layout("Analysis", content)

@app.route("/report/<report_id>/professional")
def pro_report(report_id):
    data = REPORTS.get(report_id)
    if not data:
        flash("Report expired or server restarted. Please upload the file again.")
        return redirect(url_for("index"))
    content = render_template_string(PRO, filename=data["filename"], generated=data["generated"], total=data["total"],
        counts=data["counts"], entries=data["entries"][:2000], rid=report_id)
    return layout("Professional Report", content)

@app.route("/report/<report_id>/csv")
def csv_report(report_id):
    data = REPORTS.get(report_id)
    if not data:
        flash("Report expired or server restarted. Please upload the file again.")
        return redirect(url_for("index"))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Line", "Level", "Message", "Suggested next step"])
    for entry in data["entries"]:
        writer.writerow([entry["number"], entry["level"], entry["message"], entry["advice"]])
    buffer = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    buffer.seek(0)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(data["filename"])[0]) or "log"
    return send_file(buffer, mimetype="text/csv", as_attachment=True, download_name=safe + "_report.csv")

@app.route("/about")
def about():
    content = """<section class="hero"><div class="eyebrow">About</div><h1>About Log Analyzer Pro</h1><p class="sub">A straightforward helper for reviewing plain-text application logs.</p></section><div class="card"><h2>What it does</h2><p>Identifies common severity labels, counts events, filters messages, and exports a report.</p><h2>How to use it</h2><ol><li>Choose a .log or .txt file.</li><li>Tap Analyze logs.</li><li>Search by keyword or filter by severity.</li><li>Download a CSV or printable report.</li></ol></div>"""
    return layout("About", content)

@app.route("/contact")
def contact():
    content = """<section class="hero"><div class="eyebrow">Contact</div><h1>Contact</h1><p class="sub">Questions, feedback, or suggestions.</p></section><div class="card"><p>Contact details have not yet been configured for this demo. Add your preferred public email address before promoting the site.</p></div>"""
    return layout("Contact", content)

@app.route("/privacy")
def privacy():
    content = """<section class="hero"><div class="eyebrow">Privacy</div><h1>Privacy</h1><p class="sub">A plain-language summary of this demo app.</p></section><div class="card"><h2>File handling</h2><p>Uploaded log contents are processed in server memory for analysis. Reports are temporary and may disappear when the server restarts.</p><h2>Protect sensitive data</h2><p>Logs can contain passwords, tokens, personal information, or other secrets. Remove sensitive data before uploading.</p><h2>Service logs</h2><p>Your hosting provider may maintain operational logs according to its own policies.</p></div>"""
    return layout("Privacy", content)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
