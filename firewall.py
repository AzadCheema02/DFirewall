import scapy.all as scapy
import os
import time

# Define the IP of Metasploitable2 and Kali
METASPLOITABLE2_IP = "192.168.31.139"  # Replace with the actual IP of Metasploitable2
KALI_IP = "192.168.31.135"  # Replace with Kali's IP
ALLOWED_PORTS = [22,]  # Allow SSH and HTTP

# Log rotation settings
LOG_FILE = "firewall_log.txt"
MAX_LOG_SIZE = 1024 * 1024  # 1 MB

# Define logging function with log rotation
def log_packet(packet, message):
    if os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
        os.rename(LOG_FILE, f"firewall_log_{int(time.time())}.txt")
    
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message} - {packet.summary()}\n")

# Define the packet filtering function
def packet_filter(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Packet from {ip_src} to {ip_dst}")

        # Custom Output 1: Blocking traffic from unauthorized sources to Metasploitable2
        if ip_dst == METASPLOITABLE2_IP:
            if ip_src != KALI_IP:  # Block packets from other IPs to Metasploitable2
                message = f"Blocked packet from unauthorized source {ip_src} to {ip_dst}"
                print(message)
                log_packet(packet, message)
                return  # Drop the packet

            # Custom Output 2: Allow traffic from Kali to Metasploitable2
            print(f"Allowed packet from Kali ({ip_src}) to Metasploitable2 ({ip_dst})")
            message = f"Allowed packet from Kali ({ip_src}) to Metasploitable2 ({ip_dst})"
            log_packet(packet, message)
            return packet

        if packet.haslayer(scapy.TCP):
            port = packet[scapy.TCP].dport  # Fixed closing bracket
            print(f"Packet destination port: {port}")

            # Custom Output 3: Block non-allowed ports (example: block everything except port 22 and 80)
            if port not in ALLOWED_PORTS:
                message = f"Blocked packet to port {port} (non-allowed)"
                print(message)
                log_packet(packet, message)
                return  # Drop the packet

    # Custom Output 4: Allow any other traffic and print summary
    print(f"Allowed Packet: {packet.summary()}")
    message = f"Allowed packet: {packet.summary()}"
    log_packet(packet, message)
    return packet

# Start sniffing network traffic and apply the packet filter
def start_firewall():
    print(f"Starting custom firewall...")
    scapy.sniff(prn=packet_filter, store=False)  # Listen on all interfaces

if __name__ == "__main__":
    start_firewall()  # No need to specify a network interface




