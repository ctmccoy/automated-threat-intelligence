#!/usr/bin/zsh

echo "Automated Threat Intelligence Information and Analysis"

#Move to project directory

cd ~/automated-threat-intelligence || exit 1

#Run Fetch Script
echo "[-] Gathering Threat Intelligence..."
python3 fetch_feeds.py

#Run Threat Intelligence Fetch Script
echo "[-] Analyzing Threat Intelligence Data..."
python3 analyze_data.py > output/analysis_report.txt

#Logging
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
cd output/analysis_report.txt output/analysis_report_$timestamp.txt

echo "Automated Script Completed located in output/analysis_report_$timestamp.txt
