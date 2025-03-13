import json
import os
import requests
from tabulate import tabulate

def load_json(filename):
    """Load JSON data from a file."""
    file_path = os.path.join("output", filename)
    if not os.path.exists(file_path):
        print(f"[-] File {filename} not found.")
        return None
    
    with open(file_path, "r") as file:
        return json.load(file)

def analyze_alienvault():
    """Extract and summarize key threat intelligence from AlienVault OTX data."""
    data = load_json("alienvault_otx.json")
    if not data:
        return

    print("\n📌 **AlienVault OTX Insights**")
    for pulse in data.get("results", []):
        print(f"- **{pulse['name']}** ({pulse['created']})")
        print(f"  Tags: {', '.join(pulse.get('tags', []))}")
        print(f"  Indicators: {len(pulse.get('indicators', []))} items\n")

def analyze_virustotal(ip):
    """Analyze VirusTotal threat intelligence for a given IP."""
    data = load_json(f"virustotal_{ip}.json")
    if not data:
        return

    print(f"\n📌 **VirusTotal Analysis for {ip}**")
    attributes = data.get("data", {}).get("attributes", {})
    
    analysis_stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation", 0)

    # Threat categorization
    categories = attributes.get("categories", {})
    category_list = [v for k, v in categories.items()]

    table = [
        ["Malicious Detections", analysis_stats.get("malicious", "N/A")],
        ["Harmless Detections", analysis_stats.get("harmless", "N/A")],
        ["Suspicious Detections", analysis_stats.get("suspicious", "N/A")],
        ["Reputation Score", reputation],
        ["Threat Categories", ", ".join(category_list) if category_list else "N/A"],
    ]
    print(tabulate(table, headers=["Metric", "Value"], tablefmt="grid"))

def analyze_abuseipdb(ip):
    """Analyze AbuseIPDB threat intelligence for a given IP."""
    data = load_json(f"abuseipdb_{ip}.json")
    if not data:
        return

    print(f"\n📌 **AbuseIPDB Analysis for {ip}**")
    reports = data.get("data", {})

    confidence_score = reports.get("abuseConfidenceScore", 0)

    table = [
        ["Total Reports", reports.get("totalReports", "N/A")],
        ["Abuse Confidence Score", confidence_score],
        ["Country", reports.get("countryCode", "N/A")],
        ["Last Reported", reports.get("lastReportedAt", "N/A")],
    ]
    print(tabulate(table, headers=["Metric", "Value"], tablefmt="grid"))

    if confidence_score > 50:
        print("⚠️ **This IP has a high abuse confidence score!** ⚠️")

def calculate_risk_score(ip):
    """Calculate an overall risk score based on VirusTotal and AbuseIPDB data."""
    vt_data = load_json(f"virustotal_{ip}.json")
    abuse_data = load_json(f"abuseipdb_{ip}.json")

    vt_score = 0
    abuse_score = 0

    if vt_data:
        vt_stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_score = vt_stats.get("malicious", 0) * 10  # Weight VT malicious detections higher

    if abuse_data:
        abuse_score = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)

    total_score = vt_score + abuse_score
    risk_level = "Low"

    if total_score >= 75:
        risk_level = "High"
    elif total_score >= 40:
        risk_level = "Medium"

    print(f"\n🚨 **Overall Risk Score for {ip}: {total_score} ({risk_level} Risk)** 🚨")

if __name__ == "__main__":
    analyze_alienvault()

    ip_input = input("\nEnter an IP to analyze (or press Enter to skip): ").strip()
    if ip_input:
        analyze_virustotal(ip_input)
        analyze_abuseipdb(ip_input)
        calculate_risk_score(ip_input)
