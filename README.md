# Packet Sniffer Threat Detection

README.md

# Packet Sniffer with Threat Detection

This is a simple Python-based packet sniffer that monitors live network traffic and alerts for suspicious activity based on destination ports (e.g. SSH, Telnet, RDP). Useful for basic intrusion detection or educational purposes.

---

## Features

- Captures live network packets using scapy
- Detects connections to suspicious ports:
  - SSH (22), Telnet (23), RDP (3389)
- Logs all alerts to a file
- Lightweight and terminal-based

---

## Requirements

- Python 3.x
- scapy library

Install the requirement:

bash
pip install -r requirements.txt


---

Important Notes

This script requires administrator/root privileges to sniff packets.


Run it using:

# On Linux/macOS:
sudo python main.py

# On Windows (Run CMD as Administrator):
python main.py

Windows Users Only: Install Npcap (check "WinPcap compatibility mode" during install).



---

How to Use

1. Clone the repository:



git clone https://github.com/Gogeta654/Packet-Sniffer-Threat-Detection.git
cd PacketSniffer-ThreatDetection

2. Install dependencies:



pip install -r requirements.txt

3. Run the script with admin privileges:



sudo python main.py


---

Output

Suspicious connections are logged to alerts.log, e.g.:

[2025-08-20 13:45:01] Suspicious connection: 192.168.x.x -> 192.168.x.x:23


---

# Packet Sniffer with Threat Detection usage

Open any browser or ping a site — the sniffer will pick up packets.

Or open a terminal and run something like:

curl http://example.com

If you're checking specific ports (e.g. SSH, Telnet):

nc 127.0.0.1 22

The tool logs/detects the connection — simple test case.

---

📜 License

MIT License

---