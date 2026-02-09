from flask import Flask, redirect, jsonify, request, session, send_file
import os
import json
from collections import Counter
import sqlite3
import sys
from datetime import datetime

# PDF
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont


# =============================
# PATH FIX
# =============================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from monitor.database import block_ip


# =============================
# APP SETUP
# =============================
app = Flask(__name__)
app.secret_key = "soc-secret"

LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "activity.log")
DB_FILE = os.path.join(PROJECT_ROOT, "soc.db")


# =============================
# AUTH
# =============================

def is_logged_in():
    return session.get("user") is not None


# =============================
# DB HELPERS
# =============================

def get_alerts(limit=10):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        SELECT id, time, severity, message, status
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = c.fetchall()
    conn.close()
    return rows


def acknowledge_alert(alert_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE alerts SET status='ACKNOWLEDGED' WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()


# =============================
# API
# =============================

@app.route("/api/severity")
def severity_data():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    rows = c.fetchall()
    conn.close()

    data = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for severity, count in rows:
        data[severity] = count

    return jsonify(data)


# =============================
# LOGIN
# =============================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == "analyst" and request.form.get("password") == "soc123":
            session["user"] = "analyst"
            return redirect("/")

    return """
    <h2>Analyst Login</h2>
    <form method="post">
        Username: <input name="username"><br><br>
        Password: <input name="password" type="password"><br><br>
        <button type="submit">Login</button>
    </form>
    """


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# =============================
# PDF REPORT
# =============================

@app.route("/report")
def generate_report():
    if not is_logged_in():
        return redirect("/login")

    file_path = os.path.join(PROJECT_ROOT, "incident_report.pdf")

    pdfmetrics.registerFont(UnicodeCIDFont("HeiseiMin-W3"))
    doc = SimpleDocTemplate(file_path)

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Cloud Security Incident Report", styles['Title']))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(f"Generated: {datetime.now()}", styles['Normal']))
    elements.append(Spacer(1, 20))

    alerts = get_alerts(20)

    for a in alerts:
        elements.append(Paragraph(f"{a[0]} | {a[2]} | {a[3]} | {a[4]}", styles['Normal']))
        elements.append(Spacer(1, 5))

    doc.build(elements)

    return send_file(file_path, as_attachment=True)


# =============================
# MAIN DASHBOARD
# =============================

@app.route("/")
def home():
    if not is_logged_in():
        return redirect("/login")

    try:
        with open(LOG_FILE) as f:
            logs = f.readlines()
            total_events = len(logs)
    except:
        total_events = 0

    alerts = get_alerts()
    total_alerts = len(alerts)

    alert_rows = ""

    for alert in alerts:
        alert_id, time, severity, message, status = alert

        color = {
            "HIGH": "#ff4d4f",
            "MEDIUM": "#faad14",
            "LOW": "#52c41a"
        }.get(severity, "white")

        ack_button = ""
        if status == "OPEN":
            ack_button = f"<a href='/ack/{alert_id}' style='color:#60a5fa'>ACK</a>"

        block_button = ""
        if status != "BLOCKED":
            block_button = f"<a href='/block/{alert_id}' style='color:#ff4d4f'>BLOCK</a>"

        alert_rows += f"""
        <tr>
            <td>{alert_id}</td>
            <td style='color:{color}; font-weight:bold'>{severity}</td>
            <td>{message}</td>
            <td>{status}</td>
            <td>{ack_button} {block_button}</td>
        </tr>
        """

    return f"""
    <html>
    <head>
        <title>SOC Dashboard</title>

        <meta http-equiv="refresh" content="10">

        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <style>
            body {{ background:#0f172a; color:white; font-family:Arial; padding:20px; }}
            .card {{ background:#1e293b; padding:15px; margin:10px 0; border-radius:10px; }}
            table {{ width:100%; border-collapse:collapse; }}
            th, td {{ padding:8px; border-bottom:1px solid #334155; text-align:left; }}
            a {{ text-decoration:none; font-weight:bold; margin-right:10px; }}
            canvas {{ background:white; border-radius:10px; padding:10px; }}
        </style>
    </head>
    <body>

        <h1>🚨 Cloud Security Monitoring Dashboard</h1>
        <a href="/logout">Logout</a> |
        <a href="/report">Download PDF Report</a>

        <div class="card">
            <p><b>Total Events:</b> {total_events}</p>
            <p><b>Recent Alerts:</b> {total_alerts}</p>
        </div>

        <div class="card">
            <h2>Alerts</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Message</th>
                    <th>Status</th>
                    <th>Action</th>
                </tr>
                {alert_rows}
            </table>
        </div>

        <div class="card">
            <h2>Alert Severity Distribution</h2>
            <canvas id="severityChart"></canvas>
        </div>

        <script>
        async function loadSeverityChart() {{
            const res = await fetch('/api/severity');
            const data = await res.json();

            new Chart(document.getElementById('severityChart'), {{
                type: 'pie',
                data: {{
                    labels: ['HIGH', 'MEDIUM', 'LOW'],
                    datasets: [{{
                        data: [data.HIGH, data.MEDIUM, data.LOW]
                    }}]
                }}
            }});
        }}

        loadSeverityChart();
        </script>

    </body>
    </html>
    """


@app.route("/ack/<int:alert_id>")
def ack(alert_id):
    acknowledge_alert(alert_id)
    return redirect("/")


@app.route("/block/<int:alert_id>")
def block(alert_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT message FROM alerts WHERE id = ?", (alert_id,))
    row = c.fetchone()

    if row:
        message = row[0]
        if ":" in message:
            ip = message.split(":")[-1].strip()
            block_ip(ip)

        c.execute("UPDATE alerts SET status='BLOCKED' WHERE id=?", (alert_id,))
        conn.commit()

    conn.close()
    return redirect("/")


if __name__ == "__main__":
    app.run(port=5000, debug=True)
