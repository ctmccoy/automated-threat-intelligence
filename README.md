### Automated Threat Intelligence Feed using Python

#### Gathers data and intelligence from:
    "AlienVault OTX"
    "Virus Total"
    "AbuseIPDB"

---

The Python 3 program "analyze_data.py" allows a user to input the path to a .PCAP or .PCAPNG file and receive structured data visualization.

The Python 3 program "fetch_feeds.py" allows a user to input IP addresses and receive real-time threat intelligence.  

---
#####  1 Step 1:Users run analyze_data.py and point the program to their pcap file path.  The program will process visualizations to display traffic data from the packet capture.
##### 2 Step 2: Users should record any IP addresses into the included text file "input_ips.txt" and then run "fetch_feeds.py" and the program will print any threat intelligence either of the API engines contains about those exact IP addresses.


