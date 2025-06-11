				###### analyze_data.py ######
###### This program analyzes IP addresses and prints a risk score based off any data this program finds from Threat Intelligence Databases
###### 1. A user must input IP addresses into a text file for this program to use for comparison
###### 2. A previous program should be run "fetch_feeds.py".  This program should run first to add any threat intelligence IPs from the threat feeds, to the "IPs.txt" file.  These IPs should be automatically appended to the IPs.txt file, but a user can add as many IPs as they require.

import os
import json
import logging
from datetime import datetime
from tabulate import tabulate

#logging
logging.basicConfig(filename="analyze.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

#constants for functions
OUTPUT_DIR = "output"
IP_FILE = "IPs.txt"

#creating the save file directory in /output
RUN_FOLDER_NAME = datetime.now().strftime("%Y%m%d")
RUN_DIR = os.path.join(OUTPUT_DIR, RUN_FOLDER_NAME)

#checking output directory or creating it if not existing
def get_latest_run_dir():
    if os.path.isdir(RUN_DIR):
        return RUN_DIR
    else:
        os.makedirs(RUN_DIR, exist_ok=True)
        return RUN_DIR

#loading the json and reading it and returning an error if filepath cannot be determined
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

#read and anlyze any virus total results.  Returns a warning if threat score is high, and uses tabulate to display the results neatly in the terminal
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

#the next program is what generates a risk score.  Using both databases to assign a score of low, medium, or high
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

#loads IPs from the IPs.txt file and should prompt user for manual insertio
def get_ips():
    ips = []

#load any IP addresses from the "IPs.txt" file
    if os.path.exists(IP_FILE):
        with open(IP_FILE, "r") as file:
            ips = [line.strip() for line in file if line.strip()]

#prompting the user for more IP adresses
    if os.isatty(0):
        ip_input = input("Enter IP addresses (CSV values, *Press ENTER to skip): ").strip()
        if ip_input:
            new_ips = [ip.strip() for ip in ip_input.split(",") if ip.strip()]
            ips.extend(new_ips)
#append new IPs to file
            with open(IP_FILE, "a") as file:
                for ip in new_ips:
                    file.write(ip + "\n")
    return ips

#we know what the main does right?
def main():
    run_dir = get_latest_run_dir()
    if not run_dir:
        print(f"[+] Using directory: {RUN_DIR}")
        return

    ip_list = get_ips()
    if not ip_list:
        logging.error("No IPs for analysis, exiting...")
        print("[-] No IPs for analysis.")
        return

#check if required json files were created for IPs in IPs.txt
    missing_data_ips = []
    for ip in ip_list:
        vt_path = os.path.join(run_dir, ip, "virustotal.json")
        abuseip_path = os.path.join(run_dir, ip, "abuseipdb.json")
        if not (os.path.exists(vt_path) and os.path.exists(abuseip_path)):
            if ip not in missing_data_ips:
                missing_data_ips.append(ip)

    if missing_data_ips:
        print("[-] Required JSON files are missing:")
        for ip in missing_data_ips:
            print(f"    - {ip}")
        print("\n[-] You should run 'fetch_feeds.py' first in order to gather and create the required JSON files")
        return

    output_lines = []

#analyze json files to print risk scores
    for ip in ip_list:
        analyze_virustotal(ip, run_dir, output_lines)
        analyze_abuseipdb(ip, run_dir, output_lines)
        calculate_risk_score(ip, run_dir, output_lines)

    print(f"[+] Analyzing the following IPs: {', '.join(ip_list)}")

#generating the report file names
    timestamp = datetime.now().strftime("%m%Y.txt")
    report_path = os.path.join(OUTPUT_DIR, timestamp)

#making sure the output directory exists to save the reports
    os.makedirs(OUTPUT_DIR, exist_ok=True)

#writing report and saving it in output directory
    with open(report_path, "w") as report:
        report.write("\n".join(output_lines))

    print(f"[+] Report Saved As {report_path}")

if __name__ == "__main__":
    main()
