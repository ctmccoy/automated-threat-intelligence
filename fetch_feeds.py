# ================================
# fetch_feeds.py (Updated)
# ================================

import requests
import json
import os
import time
from datetime import datetime

# Load API keys from environment variables
from config import OTX_API_KEY, VT_API_KEY, ABUSEIPDB_API_KEY

if not OTX_API_KEY or not VT_API_KEY or not ABUSEIPDB_API_KEY:
    print("[-] ERROR: One or more API keys are missing. Please set OTX_API_KEY, VT_API_KEY, and ABUSEIPDB_API_KEY.")
    exit(1)

# API URLs
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Save data helper
def save_data(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Saved to {path}")

# Fetch AlienVault pulses once per run
def fetch_alienvault(run_dir):
    print("[*] Fetching AlienVault OTX pulses...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(OTX_URL, headers=headers)
        if response.status_code == 200:
            save_data(os.path.join(run_dir, "alienvault_otx.json"), response.json())
        else:
            print(f"[-] AlienVault error: HTTP {response.status_code}")
    except Exception as e:
        print(f"[-] AlienVault exception: {e}")

# Fetch VirusTotal report for a single IP
def fetch_virustotal(ip, ip_dir):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(VT_URL + ip, headers=headers)
    if response.status_code == 200:
        save_data(os.path.join(ip_dir, "virustotal.json"), response.json())
    else:
        print(f"[-] VirusTotal error for {ip}: HTTP {response.status_code}")

# Fetch AbuseIPDB report for a single IP
def fetch_abuseipdb(ip, ip_dir):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
    if response.status_code == 200:
        save_data(os.path.join(ip_dir, "abuseipdb.json"), response.json())
    else:
        print(f"[-] AbuseIPDB error for {ip}: HTTP {response.status_code}")

# Main workflow
def main():
    timestamp = datetime.now().strftime("run_%Y-%m-%d_%H-%M-%S")
    run_dir = os.path.join("output", timestamp)
    os.makedirs(run_dir, exist_ok=True)

    # Step 1: Fetch AlienVault pulses
    fetch_alienvault(run_dir)

    # Step 2: Read IPs to analyze
    if not os.path.exists("input_ips.txt"):
        print("[-] input_ips.txt not found!")
        return

    with open("input_ips.txt") as f:
        ips = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]

    # Step 3: Fetch data per IP
    for ip in ips:
        ip_dir = os.path.join(run_dir, ip)
        fetch_virustotal(ip, ip_dir)
        fetch_abuseipdb(ip, ip_dir)
        time.sleep(2)  # Prevent hitting rate limits

if __name__ == "__main__":
    main()
