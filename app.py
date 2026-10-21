from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        f = request.files.get("logfile")
        if f:
            f.save("mylog.txt")

    q = request.args.get("q", "").lower()
    
    if not os.path.exists("mylog.txt"):
        open("mylog.txt","w").write("INFO: Level 5 Log Analyzer is LIVE!\nERROR: This is a test error - showing red\nINFO: Upload your log file to start analyzing\nERROR: Database connection failed for user 555\nINFO: User 555 login success")

    all_lines = open("mylog.txt","r").readlines()
    show_lines = [l for l in all_lines if q in l.lower()] if q else all_lines
    error_count = sum(1 for l in all_lines if "ERROR" in l)
    
    logs_html = ""
    for line in show_lines:
        color = "#ffe0e0" if "ERROR" in line else "#e0ffe0"
        border = "red" if "ERROR" in line else "green"
        logs_html += f"<div style='background:{color};padding:8px;margin:4px;border-left:4px solid {border}'>{line}</div>"

    return f"""
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Log Analyzer - Level 5</title></head>
    <body style="font-family:sans-serif;padding:15px;max-width:800px;margin:auto">
        <h2>🚀 Log Analyzer - LEVEL 5 LIVE!</h2>
        <p>Built by KINGMETUZY with phone! 🔥</p>
        <div style="display:flex;gap:10px">
            <div style="background:black;color:white;padding:15px;border-radius:10px;flex:1">Total: {len(all_lines)}</div>
            <div style="background:red;color:white;padding:15px;border-radius:10px;flex:1">Errors: {error_count}</div>
        </div><br>
        <form method="POST" enctype="multipart/form-data" style="background:#eee;padding:10px;border-radius:10px">
            <b>Upload any .txt log file:</b><br><br>
            <input type="file" name="logfile" accept=".txt,.log">
            <button style="padding:8px;background:green;color:white;border:none">Upload & Analyze</button>
        </form><br>
        <form><input name="q" value="{request.args.get('q','')}" placeholder="Search e.g 555..." style="width:60%;padding:10px">
        <button style="padding:10px;background:blue;color:white;border:none">Search</button>
        <a href="/" style="padding:10px;background:gray;color:white;text-decoration:none">Clear</a></form><hr>
        <p>Showing {len(show_lines)} logs:</p>{logs_html}
        <hr><p style="text-align:center;color:gray">Level 5 Complete ✅ - Powered by Flask</p>
    </body></html>
    """

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

