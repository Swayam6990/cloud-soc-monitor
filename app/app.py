import json
import random
import time
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "activity.log")

users = ["admin", "user1", "user2"]
ips = ["192.168.1.10", "10.0.0.5", "185.220.101.1"]  # suspicious IP included

def generate_log():
    event = {
        "time": str(datetime.now()),
        "user": random.choice(users),
        "ip": random.choice(ips),
        "action": random.choice(["login_success", "login_failed", "file_access"])
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

    print("Generated:", event)

while True:
    generate_log()
    time.sleep(2)
