# 🛡️ Automated Threat Intelligence Pipeline

This project is a lightweight pipeline for collecting and analyzing threat intelligence on IP addresses. It uses public APIs (AlienVault OTX, VirusTotal, and AbuseIPDB) to pull data about suspicious or known-malicious IPs, then scores and reports their risk level.

---

## 📅 Setup

1. **Clone this repository**  
   ```bash
   git clone https://github.com/ctmccoy/automated-threat-intelligence.git
   cd automated-threat-intelligence
   ```

2. **Install requirements (optional)**  
   If you're running inside a virtual environment:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🔐 API Keys

You’ll need API keys from the following services:

- [AlienVault OTX](https://otx.alienvault.com/api)
- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [AbuseIPDB](https://www.abuseipdb.com/account/api)

Put your keys in a local-only file called `config.py`:

```python
# config.py
OTX_API_KEY = "your_otx_key"
VT_API_KEY = "your_virustotal_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_key"
```

☠️ **Important:** Add `config.py` to `.gitignore` so it's never committed to GitHub.

---

## ✍️ Add IPs to Analyze

Edit the file `input_ips.txt` and enter one IP address per line.  
**Do not include comments or blank lines.** 
Example:

```
8.8.8.8
1.1.1.1
192.168.0.1
```

---

## 🚀 Run the Full Pipeline

Use the shell script to fetch and analyze data in one step:

```bash
./auto.sh
```

This will:

1. Fetch threat data from 3 sources
2. Store results in a timestamped directory under `output/`
3. Analyze the IPs
4. Generate a human-readable report at:
   ```
   output/analysis_report.txt
   ```

Each run will also timestamp and copy the report, for example:
```
output/analysis_report_2025-04-06_16-06-55.txt
```

---

## 📊 Output Format

- Console output includes tabulated metrics from VirusTotal and AbuseIPDB
- Risk scores are categorized as:
  - **High** (≥ 75)
  - **Medium** (40–74)
  - **Low** (< 40)

---

## ✅ Example Output

```
VIRUS TOTAL ANALYSIS FOR 8.8.8.8
+-----------------------+--------+
| Metric                | Value  |
+-----------------------+--------+
| Malicious Detections  | 2      |
| Harmless Detections   | 78     |
| Suspicious Detections | 0      |
| Reputation Score      | 10     |
| Threat Categories     | N/A    |
+-----------------------+--------+

The total risk score for 8.8.8.8: 20 (Low RISK)
```

---

## 🤝 Contributing

PRs and suggestions welcome! Please avoid submitting `config.py` or real API keys.

---

## 📄 License

[MIT](LICENSE)

---
---
---
