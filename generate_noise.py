import pandas as pd
import numpy as np
import random
import json
from datetime import datetime, timedelta

# ==========================================
# CONFIGURATION
# ==========================================
NUM_NORMAL_LOGS = 4000
OUTPUT_FILE = "cloudguard_logs.json"

# ==========================================
# DATA & HELPERS
# ==========================================
USERS = ['alice', 'bob', 'charlie', 'david', 'admin_sys']
NORMAL_PROCESSES = ['chrome.exe', 'outlook.exe', 'teams.exe', 'onedrive.exe', 'slack.exe']
MALICIOUS_PROCESSES = ['mimikatz.exe', 'crypto_miner.exe', 'nc.exe']

def get_random_ip(internal=True):
    if internal:
        return f"192.168.1.{random.randint(2, 254)}"
    return f"{random.randint(11, 199)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def get_timestamp(start_hour=9, end_hour=17):
    base_time = datetime.now() - timedelta(days=1)
    random_time = base_time.replace(hour=random.randint(start_hour, end_hour),
                                    minute=random.randint(0, 59),
                                    second=random.randint(0, 59))
    return random_time.isoformat()

# ==========================================
# GENERATION LOOP
# ==========================================
data = []
counts = {"Normal": 0, "Night_Noise": 0, "Brute_Force": 0, "Insider_Threat": 0}

# 1. NORMAL TRAFFIC
print("Generating Normal Traffic...")
for _ in range(NUM_NORMAL_LOGS):
    data.append({
        "timestamp": get_timestamp(start_hour=8, end_hour=18),
        "user": random.choice(USERS),
        "src_ip": get_random_ip(internal=True),
        "process_name": random.choice(NORMAL_PROCESSES),
        "action": "allow", "log_type": "process_execution", "label": 0
    })
    counts["Normal"] += 1

# 2. NOISE: NIGHT OWL (False Positive Generator)
print("Injecting Night Noise...")
for _ in range(450):
    data.append({
        "timestamp": get_timestamp(start_hour=1, end_hour=4),
        "user": "admin_sys",
        "src_ip": get_random_ip(internal=True),
        "process_name": "backup_service.exe",
        "action": "allow", "log_type": "system_maintenance", "label": 0
    })
    counts["Night_Noise"] += 1

# 3. ATTACK: BRUTE FORCE
print("Injecting Brute Force...")
attacker_ip = "45.133.1.55"
for _ in range(80):
    data.append({
        "timestamp": get_timestamp(start_hour=2, end_hour=4),
        "user": "admin_sys",
        "src_ip": attacker_ip,
        "process_name": "sshd",
        "action": "deny", "log_type": "auth_failure", "label": 1
    })
    counts["Brute_Force"] += 1

# 4. ATTACK: INSIDER THREAT
print("Injecting Insider Threat...")
for _ in range(70):
    data.append({
        "timestamp": get_timestamp(start_hour=11, end_hour=14),
        "user": "bob",
        "src_ip": get_random_ip(internal=True),
        "process_name": "powershell.exe",
        "action": "allow", "log_type": "process_execution", "label": 1
    })
    counts["Insider_Threat"] += 1

# ==========================================
# EXPORT & REPORT
# ==========================================
random.shuffle(data)
with open(OUTPUT_FILE, 'w') as f:
    json.dump(data, f, indent=4)

print("\n" + "="*30)
print("DATA GENERATION SUMMARY")
print("="*30)
print(f"🟢 [Normal] Standard Traffic: {counts['Normal']}")
print(f"🟡 [Noise]  Night Shift:      {counts['Night_Noise']}")
print(f"🔴 [Attack] Brute Force:      {counts['Brute_Force']}")
print(f"🔴 [Attack] Insider Threat:   {counts['Insider_Threat']}")
print("-" * 30)
print(f"TOTAL LOGS: {len(data)}")
print(f"Saved to: {OUTPUT_FILE}")