import pandas as pd
import numpy as np
import random
import json
from datetime import datetime, timedelta

# ==========================================
# CONFIGURATION
# ==========================================
NUM_NORMAL_LOGS = 4000
NUM_ANOMALIES = 200  # ~5% Contamination
OUTPUT_FILE = "cloudguard_logs.json"

# ==========================================
# HELPERS & CONSTANTS
# ==========================================
USERS = ['alice', 'bob', 'charlie', 'david', 'admin_sys']
NORMAL_PROCESSES = ['chrome.exe', 'outlook.exe', 'teams.exe', 'onedrive.exe', 'slack.exe']
MALICIOUS_PROCESSES = ['mimikatz.exe', 'powershell.exe -enc', 'nc.exe', 'cryptocli.exe']

def get_random_ip(internal=True):
    """Generate random IPs. Internal=192.168.x.x, External=Public IP"""
    if internal:
        return f"192.168.1.{random.randint(2, 254)}"
    return f"{random.randint(11, 199)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def get_timestamp(start_hour=9, end_hour=17):
    """Generate a timestamp, default is working hours"""
    base_time = datetime.now() - timedelta(days=1)
    # Random minute and second
    random_time = base_time.replace(hour=random.randint(start_hour, end_hour),
                                    minute=random.randint(0, 59),
                                    second=random.randint(0, 59))
    return random_time.isoformat()

# ==========================================
# GENERATION LOGIC
# ==========================================
data = []

# 1. GENERATE NORMAL TRAFFIC (Working hours, Internal IPs, Safe Apps)
print(f"Generating {NUM_NORMAL_LOGS} normal logs...")
for _ in range(NUM_NORMAL_LOGS):
    log = {
        "timestamp": get_timestamp(start_hour=8, end_hour=18),
        "user": random.choice(USERS),
        "src_ip": get_random_ip(internal=True),
        "process_name": random.choice(NORMAL_PROCESSES),
        "action": "allow",
        "log_type": "process_execution",
        "label": 0  # 0 = Normal
    }
    data.append(log)

# 2. INJECT ANOMALY: BRUTE FORCE (Rapid failures, External IP)
print("Injecting Brute Force Attack...")
attacker_ip = "45.133.1.55" # Static IP to simulate single attacker
for _ in range(100):
    log = {
        "timestamp": get_timestamp(start_hour=2, end_hour=4), # 3 AM attack
        "user": "admin_sys", # Targeting admin
        "src_ip": attacker_ip,
        "process_name": "sshd",
        "action": "deny", # Failed login
        "log_type": "auth_failure",
        "label": 1  # 1 = Anomaly
    }
    data.append(log)

# 3. INJECT ANOMALY: MALWARE / C2 (Weird process, unusual user)
print("Injecting Malware Execution...")
for _ in range(100):
    log = {
        "timestamp": get_timestamp(start_hour=23, end_hour=23), # Late night
        "user": "bob", # Compromised user
        "src_ip": get_random_ip(internal=True),
        "process_name": random.choice(MALICIOUS_PROCESSES),
        "action": "allow", # Firewall missed it
        "log_type": "process_execution",
        "label": 1
    }
    data.append(log)

# ==========================================
# EXPORT
# ==========================================
# Shuffle data to mimic real log stream
random.shuffle(data)

# Save to JSON
with open(OUTPUT_FILE, 'w') as f:
    json.dump(data, f, indent=4)

print(f"Success! Generated {len(data)} logs. Saved to {OUTPUT_FILE}")