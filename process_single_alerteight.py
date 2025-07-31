#!/usr/bin/env python3

import json
import os
import requests
import sys
import re
import psycopg2

# === CONFIGURATION ===

# Wazuh alert file
ALERTS_FILE = "/home/api/wazuh_pipeline/alerts_mirror.json"

# Postgres connection
POSTGRES_HOST = "192.168.132.239"
POSTGRES_PORT = 5432
POSTGRES_DB = "soc_copilot"
POSTGRES_USER = "soc_admin"
POSTGRES_PASSWORD = "root"

# Ollama config
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "phi3:mini"

# === UTILITY FUNCTIONS ===

def clean(text):
    if isinstance(text, dict) or isinstance(text, list):
        text = json.dumps(text)
    return str(text).replace("\\n", " ").replace("\n", " ").replace("'", "''").strip()

def read_alert(alert_id):
    with open(ALERTS_FILE) as f:
        for line in f:
            alert = json.loads(line)
            if str(alert.get("id", "")) == alert_id:
                return alert
    return None

def call_ollama(alert):
    prompt = f"""
You are a senior cybersecurity analyst.

You are given a Wazuh SIEM alert. Analyze it and return your response STRICTLY as valid JSON. Do not include any extra text outside the JSON.

Return the following fields exactly:

{{
  "summary": "...",
  "mitre_mapping": "...",
  "opinion": "...",
  "relevant_info": "...",
  "machine": "..."
}}

Here is the Wazuh alert:

{json.dumps(alert, indent=2)}
"""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={ "model": MODEL_NAME, "prompt": prompt, "stream": False }
        )
        response.raise_for_status()
        return response.json()["response"]
    except Exception as e:
        print(f"Error calling Ollama: {e}")
        return None

def extract_json(ai_response):
    match = re.search(r'\{.*\}', ai_response, re.DOTALL)
    if match:
        return match.group(0)
    else:
        print("AI response did not contain valid JSON.")
        return None

# === MAIN PROCESS ===

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: strict_pipeline_sql.py <alert_id>")
        sys.exit(1)

    alert_id = sys.argv[1]
    print(f"Processing alert {alert_id}")

    alert = read_alert(alert_id)
    if not alert:
        print(f"Alert {alert_id} not found!")
        sys.exit(1)

    ai_response = call_ollama(alert)
    if not ai_response:
        sys.exit(1)

    ai_json = extract_json(ai_response)
    if not ai_json:
        sys.exit(1)

    try:
        ai_data = json.loads(ai_json)
    except Exception as e:
        print(f"Failed to parse AI JSON: {e}")
        sys.exit(1)

    required_keys = ["summary", "mitre_mapping", "opinion", "relevant_info", "machine"]
    for key in required_keys:
        if key not in ai_data:
            print(f"Missing field: {key}")
            sys.exit(1)

    # Connect to Postgres
    try:
        conn = psycopg2.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD
        )
    except Exception as e:
        print(f"Failed connecting to PostgreSQL: {e}")
        sys.exit(1)

    cursor = conn.cursor()

    # Build SQL insert
    insert_sql = f"""
INSERT INTO alerts_summary (alert_id, summary, mitre_mapping, opinion, relevant_info, machine)
VALUES ({alert_id}, 
        '{clean(ai_data["summary"])}',
        '{clean(ai_data["mitre_mapping"])}',
        '{clean(ai_data["opinion"])}',
        '{clean(ai_data["relevant_info"])}',
        '{clean(ai_data["machine"])}'
);
""".strip()

    try:
        cursor.execute(insert_sql)
        conn.commit()
        print("✅ Inserted into PostgreSQL database.")
    except Exception as e:
        print(f"❌ Error inserting into PostgreSQL: {e}")
        conn.rollback()

    cursor.close()
    conn.close()
