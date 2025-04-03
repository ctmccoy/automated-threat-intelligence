#!/usr/bin/env python3

import json
import os
import argparse
from tabulate import tabulate
from datetime import datetime

#rich color
try:
    from rich import print
except ImportError:
    pass  # fallback to standard print if rich isn't available

def load_json(filename):
    """Load JSON data from a file."""
    if not os.path.exists(filename):
        print(f"[yellow][-] File not found: {filename}[/yellow]")
        return None

    with open(filename, "r") as file:
        return json.load(file)

def analyze_alienvault(otx_path):
    """Summarize AlienVault OTX data."""
    data = load_json(otx_path)
    if not data:
        return ""

    print("\n[bold cyan]=== AlienVault OTX Insights ===[/bold cyan]")
    summary_md = "### AlienVault OTX Insights\n\n"
    for pulse in data.get("results", []):
        print(f"[bold]- {pulse['name']}[/bold] ({pulse['created']})")
        print(f"  Tags: {', '.join(pulse.get('tags', []))}")
        print(f"  Indicators: {len(pulse.get('indicators', []))} items\n")

        summary_md += f"- **{pulse['name']}** ({pulse['created']})\n"
        summary_md += f"  - Tags: {', '.join(pulse.get('tags', []))}\n"
        summary_md += f"  - Indicators: {len(pulse.get('indicators', []))} items\n"

    return summary_md

#Defining API functions
# virus total function
def analyze_virustotal(ip_path):
    data = load_json(ip_path)
    if not data:
        return "", 0

    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation", 0)
    categories = ", ".join(attributes.get("categories", {}).values()) or "N/A"

    vt_score = stats.get("malicious", 0) * 10

    print(f"\n[bold magenta]=== VirusTotal Analysis for {os.path.basename(ip_path)} ===[/bold magenta]")
    table = [
        ["Malicious Detections", stats.get("malicious", "N/A")],
        ["Harmless Detections", stats.get("harmless", "N/A")],
        ["Suspicious Detections", stats.get("suspicious", "N/A")],
        ["Reputation Score", reputation],
        ["Threat Categories", categories]
    ]
    print(tabulate(table, headers=["Metric", "Value"], tablefmt="grid"))

    md = f"\n### VirusTotal Analysis for {os.path.basename(ip_path)}\n"
    md += tabulate(table, headers=["Metric", "Value"], tablefmt="github") + "\n"

    return md, vt_score

def analyze_abuseipdb(ip_path):
    data = load_json(ip_path)
    if not data:
        return "", 0

    abuse = data.get("data", {})
    score = abuse.get("abuseConfidenceScore", 0)

    print(f"\n[bold red]=== AbuseIPDB Analysis for {os.path.basename(ip_path)} ===[/bold red]")
    table = [
        ["Total Reports", abuse.get("totalReports", "N/A")],
        ["Abuse Confidence Score", score],
        ["Country", abuse.get("countryCode", "N/A")],
        ["Last Reported", abuse.get("lastReportedAt", "N/A")]
    ]
    print(tabulate(table, headers=["Metric", "Value"], tablefmt="grid"))
    if score > 50:
        print("[bold red]⚠️ This IP has a high abuse confidence score![/bold red]")

    md = f"\n### AbuseIPDB Analysis for {os.path.basename(ip_path)}\n"
    md += tabulate(table, headers=["Metric", "Value"], tablefmt="github") + "\n"

    return md, score

def calculate_risk(vt_score, abuse_score):
    total = vt_score + abuse_score
    if total >= 75:
        return "High", total
    elif total >= 40:
        return "Medium", total
    return "Low", total

def parse_args():
    parser = argparse.ArgumentParser(description="Analyze threat intelligence data from JSON files.")
    parser.add_argument("-i", "--input", default="input_ips.txt", help="Path to file with IPs (default: input_ips.txt)")
    parser.add_argument("-o", "--output", default="output", help="Folder where JSON files are stored (default: ./output)")
    parser.add_argument("--report", help="Optional: Path to save Markdown report")
    return parser.parse_args()

def main():
    args = parse_args()
    report_md = "# Threat Intelligence Summary\n"
    summary_table = []

    otx_path = os.path.join(args.output, "alienvault_otx.json")
    report_md += analyze_alienvault(otx_path)

    if not os.path.exists(args.input):
        print(f"[-] Input file not found: {args.input}")
        return

    with open(args.input, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    if not ips:
        print("[-] No IPs found to analyze.")
        return

    print(f"\n[+] Analyzing {len(ips)} IPs...\n")

    for ip in ips:
        vt_file = os.path.join(args.output, f"virustotal_{ip}.json")
        abuse_file = os.path.join(args.output, f"abuseipdb_{ip}.json")

        vt_md, vt_score = analyze_virustotal(vt_file)
        ab_md, abuse_score = analyze_abuseipdb(abuse_file)
        risk, total = calculate_risk(vt_score, abuse_score)

        report_md += vt_md + ab_md
        report_md += f"**Overall Risk for {ip}: {total} ({risk} Risk)**\n\n"

        summary_table.append([ip, vt_score, abuse_score, total, risk])

    # Final risk summary
    print("\n[bold cyan]=== Summary Risk Table ===[/bold cyan]")
    print(tabulate(summary_table, headers=["IP", "VT Score", "Abuse Score", "Total", "Risk Level"], tablefmt="grid"))

    if args.report:
        with open(args.report, "w") as f:
            f.write(report_md)
        print(f"\n[✓] Report saved to: {args.report}")

if __name__ == "__main__":
    main()
