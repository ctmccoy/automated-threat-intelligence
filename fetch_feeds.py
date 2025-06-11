					###### fetch_feeds.py ######
###### This program runs in 2 different parts, depending on the data you provide it.
###### 1. This program will fetch threat intel from Alien Vault OTX database.
###### 2. The program will analyze IPs from IPs.txt and provide any threat intelligence from the databases for each IP.
###### The output of this program can be used to run analyze_data.py to confirm a set risk score depending on the data fetch_feeds.py found from the threat intel databases.
###### The program prints current threat pulses in the terminal, but will save the full format to /output/YYYMMDD as a .json file.


import requests
import json
import os
import time
from datetime import datetime

#loading API keys and the URL
from config import OTX_API_KEY, VT_API_KEY, ABUSEIPDB_API_KEY

if not OTX_API_KEY or not VT_API_KEY or not ABUSEIPDB_API_KEY:
    print("[-] ERROR: One or more API keys are missing. Please set OTX_API_KEY, VT_API_KEY, and ABUSEIPDB_API_KEY.")
    exit(1)

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

#saved data
def save_data(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Saved to {path}")

# looping alienvault pulse feeds to print
def fetch_alienvault(run_dir):
    print("[*] Fetching AlienVault OTX pulses...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(OTX_URL, headers=headers)
        if response.status_code != 200:
            print(f"[-] AlienVault error: HTTP {response.status_code}")
            return

        data = response.json()
        save_data(os.path.join(run_dir, "AVOTX.json"), data)

#to remove dupliates from appending to IPs.txt
        ip_set = set()

        for pulse in data.get("results", []):
            title = pulse.get("name", "No Title")
            author = pulse.get("author_name", "Uknown Author")
            desc = pulse.get("description", "No Description")
            print(f"\n=== Pulse: {title} ===")
            print(f"Author: {author}")
            print(f"Description: {desc}")

            for indicator in pulse.get("indicators", []):
                ind_type = indicator.get("type")
                ind_value = indicator.get("indicator")
                if ind_type == "IPv4":
                    ip_set.add(ind_value)
                print(f" - {ind_type}: {ind_value}")

#opening IPs.txt and appending any IPs discovered from threat intel databases
        if ip_set:
            with open("IPs.txt", "w") as f:
                for ip in sorted(ip_set):
                    f.write(ip + "\n")
            print(f"[+] Appended {len(ip_set)} IPs to IPs.txt")

#exception to log any errors
    except Exception as e:
        print(f"[+] AlienVault exception: {e}")


#virus total risk indicator per each IP in IPs.txt
def fetch_virustotal(ip, ip_dir):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(VT_URL + ip, headers=headers)
    if response.status_code == 200:
        save_data(os.path.join(ip_dir, "virustotal.json"), response.json())
    else:
        print(f"[-] VirusTotal error for {ip}: HTTP {response.status_code}")

#abuse IP DB risk indicator for each IP in IPs.txt
def fetch_abuseipdb(ip, ip_dir):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
    if response.status_code == 200:
        save_data(os.path.join(ip_dir, "abuseipdb.json"), response.json())
    else:
        print(f"[-] AbuseIPDB error for {ip}: HTTP {response.status_code}")

########################
########################
#######
#creating the save file for the function
def main():
    timestamp = datetime.now().strftime("%Y%m%d")
    run_dir = os.path.join("output", timestamp)
    os.makedirs(run_dir, exist_ok=True)

#fetching alienvault intel
    fetch_alienvault(run_dir)

#reading the IPs from IPs.txt
    if not os.path.exists("IPs.txt"):
        print("[-] IPs.txt not found!")
        return

    with open("IPs.txt") as f:
        ips = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]

#using those IPs to fetch threat intel
    for ip in ips:
        ip_dir = os.path.join(run_dir, ip)
        fetch_virustotal(ip, ip_dir)
        fetch_abuseipdb(ip, ip_dir)

	#rate limiter adding 2 second between each IP
        time.sleep(2)

if __name__ == "__main__":
    main()
