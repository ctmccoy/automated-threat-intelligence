
# ================================
# ./auto.sh
# ================================

#!/usr/bin/zsh


echo "🚀 Starting Automated Threat Intelligence Pipeline"

cd ~/automated-threat-intelligence || exit 1

# Step 1: Fetch feeds
echo "[+] Running fetch_feeds.py"
python3 fetch_feeds.py

# Step 2: Analyze fetched data
echo "[+] Running analyze_data.py"
python3 analyze_data.py

# Step 3: Timestamped copy of the report
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
cp output/analysis_report.txt output/analysis_report_$timestamp.txt

echo "✅ All done. Timestamped report: output/analysis_report_$timestamp.txt"
