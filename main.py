from scapy.all import sniff, IP, TCP
from datetime import datetime

SUSPICIOUS_PORTS = [22, 23, 3389]  # SSH, Telnet, RDP

def detect_threat(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        if dst_port in SUSPICIOUS_PORTS:
            log_threat(src_ip, dst_ip, dst_port)

def log_threat(src, dst, port):
    alert = f"[{datetime.now()}] Suspicious connection: {src} -> {dst}:{port}"
    print(alert)
    with open("alerts.log", "a") as log_file:
        log_file.write(alert + "\n")

print("Starting packet capture... (Press Ctrl+C to stop)")
sniff(filter="tcp", prn=detect_threat, store=0)