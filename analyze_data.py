# ================================
# analyze_data.py (Updated)
# ================================

import os
import json
import logging
from datetime import datetime

def get_latest_run_dir(base_dir="output"):
    runs = [d for d in os.listdir(base_dir) if d.startswith("run_")]
    if not runs:
        return None
    runs.sort(reverse=True)
    return os.path.join(base_dir, runs[0])

def load_json(path):
    if not os.path.exists(path):
        logging.error("The file %s was not found!", path)
        print(f"[-] File {path} not found.")
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.error("Error decoding JSON from %s: %s", path, e)
        return None

def analyze_ip(ip, run_dir):
    vt_data = load_json(os.path.join(run_dir, ip, "virustotal.json"))
    abuse_data = load_json(os.path.join(run_dir, ip, "abuseipdb.json"))

    vt_score = 0
    abuse_score = 0

    print(f"\n========= Analysis for {ip} =========")

    if vt_data:
        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_score = stats.get("malicious", 0) * 10
        print(f"[VT] Malicious: {stats.get('malicious', 'N/A')}, Suspicious: {stats.get('suspicious', 'N/A')}, Harmless: {stats.get('harmless', 'N/A')}")

    if abuse_data:
        abuse_score = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)
        print(f"[AbuseIPDB] Confidence Score: {abuse_score}, Total Reports: {abuse_data.get('data', {}).get('totalReports', 'N/A')}")

    total_score = vt_score + abuse_score
    if total_score >= 75:
        risk = "High"
    elif total_score >= 40:
        risk = "Medium"
    else:
        risk = "Low"
    print(f"The total risk score for {ip}: {total_score} ({risk} RISK)")

def main():
    logging.basicConfig(filename="analyze.log", level=logging.ERROR)

    run_dir = get_latest_run_dir()
    if not run_dir:
        print("[-] No run_* directory found in output/.")
        return

    ip_file = "input_ips.txt"
    if not os.path.exists(ip_file):
        print("[-] input_ips.txt not found!")
        return

    with open(ip_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    for ip in ips:
        analyze_ip(ip, run_dir)

if __name__ == "__main__":
    main()
