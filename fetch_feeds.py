#Python3 program to fetch threat intelligence from 3 updated feeds
#!/usr/bin/env python3

import requests
import json
import os
import argparse
from datetime import datetime

# Load API Keys from environment variables
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Validate API Keys
if not OTX_API_KEY or not VT_API_KEY or not ABUSEIPDB_API_KEY:
    print("[-] ERROR: One or more API keys are missing. Please check your ~/.zshrc or environment variables.")
    exit(1)

# API Endpoints
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def save_json(output_path, data):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[✓] Data saved to {output_path}")

def fetch_alienvault_feeds(output_dir):
    print("[*] Fetching AlienVault OTX feeds...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(OTX_URL, headers=headers)
        if response.status_code == 200:
            data = response.json()
            save_json(os.path.join(output_dir, "alienvault_otx.json"), data)
        else:
            print(f"[-] OTX Error {response.status_code}: {response.text}")
    except requests.RequestException as e:
        print(f"[-] Error connecting to OTX: {e}")

def fetch_virustotal_data(ip, output_dir):
    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL + ip
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            save_json(os.path.join(output_dir, ip, "virustotal.json"), data)
        elif response.status_code == 429:
            print(f"[!] VirusTotal rate limit hit for IP {ip}.")
        else:
            print(f"[-] VirusTotal Error {response.status_code}: {response.text}")
    except requests.RequestException as e:
        print(f"[-] Error fetching VirusTotal data for {ip}: {e}")

def fetch_abuseipdb_data(ip, output_dir):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            save_json(os.path.join(output_dir, ip, "abuseipdb.json"), data)
        elif response.status_code == 429:
            print(f"[!] AbuseIPDB rate limit hit for IP {ip}.")
        else:
            print(f"[-] AbuseIPDB Error {response.status_code}: {response.text}")
    except requests.RequestException as e:
        print(f"[-] Error fetching AbuseIPDB data for {ip}: {e}")

def get_ip_list(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    else:
        print(f"[-] IP file not found: {file_path}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Fetch threat intel from AlienVault, VirusTotal, and AbuseIPDB.")
    parser.add_argument("-i", "--input", default="input_ips.txt", help="Path to input file with IP addresses")
    parser.add_argument("--skip-otx", action="store_true", help="Skip AlienVault OTX feed")
    parser.add_argument("-o", "--output", default="output", help="Directory to save output")
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = os.path.join(args.output, f"run_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n[+] Output will be saved to: {output_dir}\n")

    if not args.skip_otx:
        fetch_alienvault_feeds(output_dir)

    ip_list = get_ip_list(args.input)
    print(f"[+] Loaded {len(ip_list)} IP(s) from {args.input}")

    for ip in ip_list:
        print(f"\n[*] Fetching data for IP: {ip}")
        fetch_virustotal_data(ip, output_dir)
        fetch_abuseipdb_data(ip, output_dir)

    print(f"\n[✓] Threat intelligence collection complete. Results stored in '{output_dir}'.")

if __name__ == "__main__":
    main()
