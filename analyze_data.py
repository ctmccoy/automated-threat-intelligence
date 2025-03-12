import json
import os

def load_json(filename):
    """Load JSON data from a file."""
    file_path = os.path.join("output", filename)
    if not os.path.exists(file_path):
        print(f"[-] File {filename} not found.")
        return None
    
    with open(file_path, "r") as file:
        return json.load(file)

def analyze_alienvault():
    """Extract key details from AlienVault OTX data."""
    data = load_json("alienvault_otx.json")
    if not data:
        return

    print("\n📌 AlienVault OTX Insights:")
    for pulse in data.get("results", []):
        print(f"- {pulse['name']} ({pulse['created']}) | Tags: {', '.join(pulse.get('tags', []))}")

def analyze_virustotal(ip):
    """Extract key details from VirusTotal data."""
    data = load_json(f"virustotal_{ip}.json")
    if not data:
        return

    print(f"\n📌 VirusTotal Insights for {ip}:")
    attributes = data.get("data", {}).get("attributes", {})
    if attributes.get("last_analysis_stats"):
        print(f"- Malicious detections: {attributes['last_analysis_stats']['malicious']}")
        print(f"- Harmless detections: {attributes['last_analysis_stats']['harmless']}")

def analyze_abuseipdb(ip):
    """Extract key details from AbuseIPDB data."""
    data = load_json(f"abuseipdb_{ip}.json")
    if not data:
        return

    print(f"\n📌 AbuseIPDB Insights for {ip}:")
    reports = data.get("data", {})
    print(f"- Total reports: {reports.get('totalReports', 'N/A')}")
    print(f"- Confidence score: {reports.get('abuseConfidenceScore', 'N/A')}")

if __name__ == "__main__":
    analyze_alienvault()

    # Ask for user input to analyze specific IP reports
    ip_input = input("\nEnter an IP to analyze (or press Enter to skip): ").strip()
    if ip_input:
        analyze_virustotal(ip_input)
        analyze_abuseipdb(ip_input)
