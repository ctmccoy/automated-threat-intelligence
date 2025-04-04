## Automated Threat Intelligence Feed using Python

- 1️⃣ Gathers updated threat intelligence from "AlienVault OTX" "Virus Total" "AbuseIPDB".
- 2️⃣ Generates threat intelligence from user created list of IP addresses.
- 3️⃣ Visualizes any data found from the threat intelligence and provides a risk score assessment.


---

### Workflow ➡️ End-to-End Pipeline:


#### 🕵️ Step 1: Fetch Data from Intelligence Feeds
Use *`fetch_feeds.py`* to:
- Pull global threat data from AlienVault OTX
- Query VirusTotal and AbuseIPDB for each IP in input_ips.txt
- Save all results in structured JSON format under output/

🖥️ How to Run `fetch_feeds.py`:

    cd automated-threat-intelligence
    python3 fetch_feeds.py

#### 🔍 Step 2: Analyze & Summarize the Results
Use *`analyze_data.py`* to:
- Parse the JSON results in output/
- Generate readable summaries
- Calculate overall risk scores for each IP

🖥️ How to Run `analyze_data.py`:

    cd automated-threat-intelligence
    python3 analyze_data.py
---
---
---

## 🔐 Instructions for obtaining API keys from `VirusTotal`, `AlienVault OTX`, and `AbuseIPDB`

To use the `fetch_feeds.py` script, you need API keys from three services:

- [VirusTotal](https://www.virustotal.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)

You must set these keys as environment variables in your shell configuration file (e.g., `~/.zshrc` or `~/.bashrc`).

---

### 1. 🧪 VirusTotal API Key

#### 📝 Steps:
1. Go to [https://www.virustotal.com/](https://www.virustotal.com/) and **sign up** for a free account.
2. After logging in, click your profile icon (top-right) → **API Key**.
3. Copy your **Public API key**.

#### 🔧 Set it in your terminal:
```bash
echo 'export VT_API_KEY="your_virustotal_api_key_here"' >> ~/.zshrc
source ~/.zshrc
```

---

### 2. 👽 AlienVault OTX API Key

#### 📝 Steps:
1. Visit [https://otx.alienvault.com/](https://otx.alienvault.com/) and **create an account**.
2. After logging in, click your profile image → **My Profile** → **API Key** tab.
3. Copy the API key listed there.

#### 🔧 Set it in your terminal:
```bash
echo 'export OTX_API_KEY="your_alienvault_otx_key_here"' >> ~/.zshrc
source ~/.zshrc
```

---

### 3. 🚨 AbuseIPDB API Key

#### 📝 Steps:
1. Go to [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register) and create a free account.
2. After logging in, navigate to [https://www.abuseipdb.com/account/api](https://www.abuseipdb.com/account/api).
3. Generate an API key (you can use the free tier).

#### 🔧 Set it in your terminal:
```bash
echo 'export ABUSEIPDB_API_KEY="your_abuseipdb_key_here"' >> ~/.zshrc
source ~/.zshrc
```

---

### ✅ Verifying Your Keys in Python

To confirm your keys are properly set, run:

```python
import os
print("VT:", os.getenv("VT_API_KEY"))
print("OTX:", os.getenv("OTX_API_KEY"))
print("AbuseIPDB:", os.getenv("ABUSEIPDB_API_KEY"))
```
---
---
---
