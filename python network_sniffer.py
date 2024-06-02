import argparse
import logging
from scapy.all import sniff, IP, TCP, UDP

# إعداد التسجيل
logging.basicConfig(filename='network_traffic.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        log_message = f"IP Packet: {ip_src} -> {ip_dst}"
        
        if TCP in packet:
            log_message += f" | TCP Packet: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}"
        elif UDP in packet:
            log_message += f" | UDP Packet: {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}"
        
        # طباعة وتسجيل الرسالة
        print(log_message)
        logging.info(log_message)

def start_sniffing(interface, packet_count):
    print(f"[*] Starting sniffing on {interface}")
    sniff(iface=interface, prn=packet_callback, store=0, count=packet_count)

def main():
    # إعداد تحليل سطر الأوامر
    parser = argparse.ArgumentParser(description="Simple Network Sniffer")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument('-c', '--count', type=int, default=0, help="Number of packets to capture (0 for infinite)")
    
    args = parser.parse_args()
    
    try:
        start_sniffing(args.interface, args.count)
    except PermissionError:
        print("Error: Please run the script with root privileges.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
