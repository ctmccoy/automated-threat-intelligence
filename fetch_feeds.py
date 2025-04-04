# ================================
# fetch_feeds.py
# ================================


import requests
import json
import os
from datetime import datetime
import time

# Load API keys
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not OTX_API_KEY or not VT_API_KEY or not ABUSEIPDB_API_KEY:
    print("[-] ERROR: One or more API keys are missing. Check your environment variables.")
    exit(1)

# API URLs
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def save_data(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Saved to {path}")

def fetch_alienvault(run_dir):
    print("[*] Fetching AlienVault OTX...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(OTX_URL, headers=headers)
        if r.status_code == 200:
            save_data(os.path.join(run_dir, "alienvault_otx.json"), r.json())
        else:
            print(f"[-] AlienVault error: {r.status_code}")
    except Exception as e:
        print(f"[-] AlienVault exception: {e}")

def fetch_virustotal(ip, path):
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(VT_URL + ip, headers=headers)
    if r.status_code == 200:
        save_data(os.path.join(path, "virustotal.json"), r.json())
    else:
        print(f"[-] VT error for {ip}: {r.status_code}")

def fetch_abuseipdb(ip, path):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
    if r.status_code == 200:
        save_data(os.path.join(path, "abuseipdb.json"), r.json())
    else:
        print(f"[-] AbuseIPDB error for {ip}: {r.status_code}")

def main():
    timestamp = datetime.now().strftime("run_%Y-%m-%d_%H-%M-%S")
    run_dir = os.path.join("output", timestamp)
    os.makedirs(run_dir, exist_ok=True)

    # AlienVault once per run
    fetch_alienvault(run_dir)

    # Load IPs
    if not os.path.exists("input_ips.txt"):
        print("[-] input_ips.txt not found!")
        return

    with open("input_ips.txt") as f:
        ips = [line.strip() for line in f if line.strip()]

    for ip in ips:
        ip_dir = os.path.join(run_dir, ip)
        fetch_virustotal(ip, ip_dir)
        fetch_abuseipdb(ip, ip_dir)
        time.sleep(2)  # Prevent API rate limits

if __name__ == "__main__":
    main()
