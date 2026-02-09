import json
import os
from collections import defaultdict
from datetime import datetime
from database import insert_event, insert_alert, is_ip_blocked

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "activity.log")

FAILED_LIMIT = 5

BLACKLIST_IPS = ["185.220.101.1"]

failed_count = defaultdict(int)
seen_ips = set()

# prevent duplicate alerts during runtime
triggered_alerts = set()


def write_alert(message, severity):
    key = f"{severity}:{message}"
    if key in triggered_alerts:
        return
    triggered_alerts.add(key)

    insert_alert(severity, message)
    print("ALERT:", severity, message)


def process_logs():
    if not os.path.exists(LOG_FILE):
        return

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    now = datetime.now()

    # for spike detection
    recent_events = 0

    for line in lines:
        event = json.loads(line)

        insert_event(event)

        ip = event["ip"]
        user = event["user"]
        action = event["action"]

        # 🚫 skip blocked
        if is_ip_blocked(ip):
            continue

        # =============================
        # RULE BASED
        # =============================

        if ip in BLACKLIST_IPS:
            write_alert(f"Blacklisted IP detected: {ip}", "HIGH")

        if action == "login_failed":
            failed_count[user] += 1
            if failed_count[user] >= FAILED_LIMIT:
                write_alert(f"Brute force suspected for user: {user}", "MEDIUM")

        # =============================
        # ANOMALY 1 — unusual hour
        # =============================
        hour = now.hour
        if action == "login_success" and (hour >= 0 and hour <= 5):
            write_alert(f"Unusual login hour for user {user}", "MEDIUM")

        # =============================
        # ANOMALY 2 — new IP
        # =============================
        if ip not in seen_ips:
            seen_ips.add(ip)
            write_alert(f"New IP observed: {ip}", "LOW")

        # =============================
        # ANOMALY 3 — spike
        # =============================
        recent_events += 1

    if recent_events > 20:
        write_alert("Activity spike detected", "HIGH")


if __name__ == "__main__":
    process_logs()
