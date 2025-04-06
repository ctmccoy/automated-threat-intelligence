# ================================
# analyze_data.py (Combined Version)
# ================================

import os
import json
import logging
from datetime import datetime
from tabulate import tabulate

# Logging setup
logging.basicConfig(filename="analyze.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
OUTPUT_DIR = "output"
IP_FILE = "input_ips.txt"

def get_latest_run_dir(base_dir=OUTPUT_DIR):
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
        with open(path, "r") as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        logging.error("Error decoding JSON from %s: %s", path, e)
        return None

def analyze_virustotal(ip, run_dir, output_lines):
    data = load_json(os.path.join(run_dir, ip, "virustotal.json"))
    if not data:
        return

    attributes = data.get("data", {}).get("attributes", {})
    analysis_stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation", 0)
    category_list = list(attributes.get("categories", {}).values())

    header = f"VIRUS TOTAL ANALYSIS FOR {ip}"
    table = [
        ["Malicious Detections", analysis_stats.get("malicious", "N/A")],
        ["Harmless Detections", analysis_stats.get("harmless", "N/A")],
        ["Suspicious Detections", analysis_stats.get("suspicious", "N/A")],
        ["Reputation Score", reputation],
        ["Threat Categories", ", ".join(category_list) if category_list else "N/A"],
    ]

    result = f"\n{header}\n" + tabulate(table, headers=["Metric", "Value"], tablefmt="grid")
    print(result)
    output_lines.append(result)

def analyze_abuseipdb(ip, run_dir, output_lines):
    data = load_json(os.path.join(run_dir, ip, "abuseipdb.json"))
    if not data:
        return

    reports = data.get("data", {})
    confidence_score = reports.get("abuseConfidenceScore", 0)

    header = f"ABUSE IP DB for {ip}"
    table = [
        ["Total Reports", reports.get("totalReports", "N/A")],
        ["Abuse Confidence Score", confidence_score],
        ["Location (Country)", reports.get("countryCode", "N/A")],
        ["Last Reported", reports.get("lastReportedAt", "N/A")],
    ]

    result = f"\n{header}\n" + tabulate(table, headers=["Metric", "Value"], tablefmt="grid")
    print(result)
    output_lines.append(result)

    if confidence_score > 50:
        warning = "WARNING - HIGH abuse score!!!"
        print(warning)
        output_lines.append(warning)

def calculate_risk_score(ip, run_dir, output_lines):
    vt_data = load_json(os.path.join(run_dir, ip, "virustotal.json"))
    abuse_data = load_json(os.path.join(run_dir, ip, "abuseipdb.json"))

    vt_score = 0
    abuse_score = 0

    if vt_data:
        vt_stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_score = vt_stats.get("malicious", 0) * 10
    if abuse_data:
        abuse_score = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)

    total_score = vt_score + abuse_score
    risk_level = "Low"
    if total_score >= 75:
        risk_level = "High"
    elif total_score >= 40:
        risk_level = "Medium"

    summary = f"The total risk score for {ip}: {total_score} ({risk_level} RISK)"
    print(summary)
    output_lines.append(summary + "\n")

def get_ips():
    if os.path.exists(IP_FILE):
        with open(IP_FILE, "r") as file:
            return [line.strip() for line in file if line.strip()]
    if os.isatty(0):
        ip_input = input("ENTER AN IP FOR ANALYSIS: ").strip()
        return [ip.strip() for ip in ip_input.split(",") if ip.strip()]
    return []

def main():
    run_dir = get_latest_run_dir()
    if not run_dir:
        print("[-] No run_* directory found in output/.")
        return

    ip_list = get_ips()
    if not ip_list:
        logging.error("No IPs for analysis, exiting...")
        print("[-] No IPs for analysis.")
        return

    output_lines = []
    for ip in ip_list:
        analyze_virustotal(ip, run_dir, output_lines)
        analyze_abuseipdb(ip, run_dir, output_lines)
        calculate_risk_score(ip, run_dir, output_lines)

    # Write to output report
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "analysis_report.txt"), "w") as report:
        report.write("\n".join(output_lines))

    print("[+] Report written to output/analysis_report.txt")

if __name__ == "__main__":
    main()