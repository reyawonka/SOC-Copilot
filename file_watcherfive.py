#!/usr/bin/env python3
import time
import json
import os
import requests
import glob

# === CONFIGURATION ===
ALERTS_FILE = "/home/api/wazuh_pipeline/alerts_mirror.json"
CHECKPOINT_FILE = "/home/api/wazuh_pipeline/last_processed_alert_id.txt"
AI_PENDING_DIR = "/home/api/wazuh_pipeline/ai_pending"
AI_INPUTS_DIR = "/home/api/wazuh_pipeline/ai_inputs"

# Rundeck webhook URL:
RUNDECK_WEBHOOK_URL = "http://localhost:4440/api/52/webhook/VmHNV0uXNjlpdOGKM4Tp02coLx0Eet1j#New_Hook"

# === SETTINGS ===
POLL_INTERVAL_SECONDS = 2
SEVERITY_THRESHOLD = 10  # changed from 10 → 7
# ====================

# === CLEANUP ===
# Delete old alert_*.txt files in ai_pending
os.makedirs(AI_PENDING_DIR, exist_ok=True)
for file_path in glob.glob(f"{AI_PENDING_DIR}/alert_*.txt"):
    try:
        os.remove(file_path)
        print(f"🧹 Deleted old pending file: {file_path}")
    except Exception as e:
        print(f"❌ Error deleting {file_path}: {e}")

# === FUNCTIONS ===

def trigger_rundeck():
    try:
        r = requests.post(RUNDECK_WEBHOOK_URL, verify=False)
        print(f"Triggered Rundeck webhook → HTTP {r.status_code}")
    except Exception as e:
        print(f"Error triggering Rundeck webhook: {e}")

def process_alerts():
    last_id = 0
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "r") as f:
            try:
                last_id = int(f.read().strip())
            except:
                last_id = 0

    with open(ALERTS_FILE, "r") as f:
        alerts = [json.loads(line) for line in f if line.strip()]

    os.makedirs(AI_INPUTS_DIR, exist_ok=True)
    os.system(f"cp {ALERTS_FILE} {AI_INPUTS_DIR}/alerts.json")
    print(f"Copied alerts_mirror.json → ai_inputs")

    new_alerts = [
        a for a in alerts
        if int(float(a.get("id", 0))) > last_id and int(a.get("rule", {}).get("level", 0)) >= SEVERITY_THRESHOLD
    ]

    if new_alerts:
        print(f"\n=== Found {len(new_alerts)} new alerts ===")
        os.makedirs(AI_PENDING_DIR, exist_ok=True)

        for a in new_alerts:
            aid = str(a["id"])
            pending_file = f"{AI_PENDING_DIR}/alert_{aid}.txt"

            with open(pending_file, "w") as f:
                f.write(aid)

            print(f"Queued alert {aid} → {pending_file}")

            trigger_rundeck()
            time.sleep(0.2)

        max_id = max(int(float(a["id"])) for a in new_alerts)
        with open(CHECKPOINT_FILE, "w") as f:
            f.write(str(max_id))

# === MAIN LOOP ===

if __name__ == "__main__":
    print(f"🚀 Starting severity watcher on {ALERTS_FILE}")
    print(f"Polling every {POLL_INTERVAL_SECONDS} seconds...")
    while True:
        try:
            process_alerts()
            time.sleep(POLL_INTERVAL_SECONDS)
        except Exception as e:
            print(f"Error in process_alerts(): {e}")
            time.sleep(5)
