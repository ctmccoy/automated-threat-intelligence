import requests
import json
import os

# Load API Keys from environment variables
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Check if API keys are set
if not OTX_API_KEY or not VT_API_KEY or not ABUSEIPDB_API_KEY:
    print("[-] ERROR: One or more API keys are missing. Please check your ~/.zshrc.")
    exit(1)

# API Endpoints
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def fetch_alienvault_feeds():
    """Fetch threat intelligence data from AlienVault OTX."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    try:
        response = requests.get(OTX_URL, headers=headers)
        if response.status_code == 200:
            data = response.json()
            save_data("alienvault_otx.json", data)
            print("[+] AlienVault OTX data fetched successfully.")
        else:
            print(f"[-] Failed to fetch AlienVault data: {response.status_code}, {response.text}")

    except requests.RequestException as e:
        print(f"[-] Error connecting to AlienVault OTX: {e}")

def fetch_virustotal_data(ip):
    """Fetch threat intelligence data from VirusTotal for a given IP."""
    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL + ip
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            save_data(f"virustotal_{ip}.json", data)
            print(f"[+] VirusTotal data for {ip} fetched successfully.")
        else:
            print(f"[-] Failed to fetch VirusTotal data: {response.status_code}, {response.text}")

    except requests.RequestException as e:
        print(f"[-] Error connecting to VirusTotal: {e}")

def fetch_abuseipdb_data(ip):
    """Fetch threat intelligence data from AbuseIPDB for a given IP."""
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            save_data(f"abuseipdb_{ip}.json", data)
            print(f"[+] AbuseIPDB data for {ip} fetched successfully.")
        else:
            print(f"[-] Failed to fetch AbuseIPDB data: {response.status_code}, {response.text}")

    except requests.RequestException as e:
        print(f"[-] Error connecting to AbuseIPDB: {e}")

def save_data(filename, data):
    """Save data to the output folder as JSON."""
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    
    print(f"[+] Data saved to {output_path}")

if __name__ == "__main__":
    fetch_alienvault_feeds()
    
    # Example IP addresses to check (can be modified)
    test_ips = ["8.8.8.8", "1.1.1.1"]

    for ip in test_ips:
        fetch_virustotal_data(ip)
        fetch_abuseipdb_data(ip)
