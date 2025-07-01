from scapy.all import sniff, IP, TCP
import logging
import subprocess

# List of allowed IPs
allowed_ips = ["192.168.1.100", "192.168.1.101"]  # Replace with your allowed IPs

# List of allowed ports (e.g., SSH: 22, HTTP: 80)
allowed_ports = [22, 80]

# Logging setup
logging.basicConfig(
    filename='/tmp/firewall_logs.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Function to add iptables rule to block a specific IP
def block_ip(ip):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    logging.warning(f"Blocked IP: {ip}")
    print(f"Blocked IP: {ip}")

# Function to add iptables rule to block a specific port
def block_port(port):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])
    logging.warning(f"Blocked port: {port}")
    print(f"Blocked port: {port}")

# Function to process each packet
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Check if the source IP is allowed
        if ip_src not in allowed_ips:
            logging.warning(f"Blocked packet from unauthorized IP: {ip_src} -> {ip_dst}")
            print(f"Blocked packet from unauthorized IP: {ip_src} -> {ip_dst}")
            block_ip(ip_src)
            return

        # If packet is TCP, check the destination port
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
