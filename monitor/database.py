import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILE = os.path.join(BASE_DIR, "soc.db")


# =============================
# INIT DATABASE
# =============================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Events table
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            user TEXT,
            ip TEXT,
            action TEXT
        )
    """)

    # Alerts table
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            severity TEXT,
            message TEXT,
            status TEXT
        )
    """)

    # Blocked IPs table
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            time TEXT
        )
    """)

    conn.commit()
    conn.close()


# =============================
# INSERT OPERATIONS
# =============================

def insert_event(event):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        INSERT INTO events (time, user, ip, action)
        VALUES (?, ?, ?, ?)
    """, (event["time"], event["user"], event["ip"], event["action"]))

    conn.commit()
    conn.close()


def insert_alert(severity, message):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        INSERT INTO alerts (time, severity, message, status)
        VALUES (?, ?, ?, ?)
    """, (str(datetime.now()), severity, message, "OPEN"))

    conn.commit()
    conn.close()


# =============================
# ALERT ACTIONS
# =============================

def acknowledge_alert(alert_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        UPDATE alerts
        SET status = 'ACKNOWLEDGED'
        WHERE id = ?
    """, (alert_id,))

    conn.commit()
    conn.close()


# =============================
# BLOCKLIST
# =============================

def block_ip(ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        INSERT OR IGNORE INTO blocked_ips (ip, time)
        VALUES (?, ?)
    """, (ip, str(datetime.now())))

    conn.commit()
    conn.close()


def is_ip_blocked(ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
    result = c.fetchone()

    conn.close()
    return result is not None
