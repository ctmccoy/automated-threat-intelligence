Automated Threat Intelligence Feed using Python


**MIT License


Gathers data and intelligence from:
    "AlienVault OTX"
    "Virus Total"
    "AbuseIPDB"


The Python 3 program "fetch_feeds.py" allows a user to input IP addresses and receive real-time threat intelligence.  
The Python 3 program "analyze_data.py" allows a user to input the path to a .PCAP or .PCAPNG file and receive structured data visualization.

Users can load IPs from the analysis into the input_ips.txt file and the program will automatically reference those IPs against known vulnerability databases to return malicious intent rating for user.


