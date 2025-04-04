#!/usr/bin/zsh

# ================================
# ./auto.sh
# ================================

echo "Automated Threat Intelligence Information and Analysis"

#move to project directory
cd ~/automated-threat-intelligence || exit 1

# running fetch script
echo "[-] Gathering Threat Intelligence..."
python3 fetch_feeds.py

# run analysis script
echo "[-] Analyzing Threat Intelligence Data..."
python3 analyze_data.py > output/analysis_report.txt

#log function for management
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
cd output/analysis_report.txt output/analysis_report_$timestamp.txt

echo "Automated Script Completed located in output/analysis_report_$timestamp.txt
