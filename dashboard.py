from flask import Flask, render_template, jsonify, Response
import json, os, csv, io, time

app = Flask(__name__)
LOG_FILE = "logs.json"

def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except:
        return []

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/dashboard")
def dashboard_api():
    logs = read_logs()

    high = sum(1 for l in logs if l.get("severity") == "HIGH")
    medium = sum(1 for l in logs if l.get("severity") == "MEDIUM")
    low = sum(1 for l in logs if l.get("severity") == "LOW")

    total_scanned = len(logs) * 5  # heuristic: 1 alert ≈ 5 files scanned
    threats_blocked = high
    suspicious = medium + low

    system_health = max(100 - (high * 5 + medium * 2), 70)

    return jsonify({
        "stats": {
            "total_scanned": total_scanned,
            "threats_blocked": threats_blocked,
            "suspicious": suspicious,
            "system_health": system_health
        },
        "logs": logs[-50:]
    })


@app.route("/api/export/csv")
def export_csv():
    if not os.path.exists(LOG_FILE):
        return Response("", mimetype="text/csv")

    with open(LOG_FILE, "r") as f:
        logs = json.load(f)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Time", "File", "Process", "Severity", "Reasons", "Action"])
    for l in logs:
        writer.writerow([
            l.get("time"),
            l.get("file"),
            l.get("process"),
            l.get("severity"),
            "; ".join(l.get("reasons", [])),
            l.get("action")
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=ransomware_logs.csv"}
    )


if __name__ == "__main__":
    app.run(debug=True)




# ... keep existing code ...

