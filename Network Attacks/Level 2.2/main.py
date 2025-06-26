from scapy.all import *
from datetime import datetime, timedelta
import platform
import hashlib
from threshold import Threshold

# Threat intelligence
# ADD YOUR C2 SERVER IPS HERE
MALICIOUS_IPS = ["4.2.2.2"]
MALICIOUS_DOMAINS = ["virus.com"]
MALICIOUS_HASHES = {
    "b3f067e63fff8e171ee26bcde6a6010737c8b22c":"LokiBot",
    "73480f2548244fb6a3e9db83a4e74082dd2fa500":"LokiBot",
    "efbd4555c4b881d77d28f659289373a813e79650":"TeslaCrypt",
    "13427e27f405ea2c818d4f55745cd9fb9e336134":"TeslaCrypt"
}

# dict to track tcp streams
tcp_streams = {}
# dict to track alerts
alert_history = {}
# set a timeout to ignore repeated alerts within 10s
REPEATED_ALERT_TIMEOUT = timedelta(seconds=10)

'''
    ARP Scan
    group_key: lambda p:p[Ether].src
    unique_key: lambdap:p[ARP].pdst
'''
arp_threshold = Threshold(
    count=5,
    windows=10,
    group_key=lambda p: p[Ether].src,
    unique_key=lambda p: p[ARP].pdst
)

tcp_threshold = Threshold(
    count=50, # Scan 50 ports in 10 seconds
    windows=10,
    group_key=lambda p: p[Ether].src,
    unique_key=lambda p: (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
)

def get_interface():
    """
    checks for the OS and returns the correct network interface
    """
    print("Checking for OS...")
    if platform.system() == "Windows":
        print("OS is Windows -> VMware Network Adapter VMnet1")
        return "VMware Network Adapter VMnet1"
    elif platform.system() == "Darwin":  # macOS is identified as 'Darwin'
        print("OS is Mac -> vmenet3")
        return "vmenet3"
    else:
        raise RuntimeError("Only supports windows/mac")
 
 
def alert(msg):
    """
    alerts function to check if the alert has been logged before within the timeout
    """
    # ignore the alert if it has already been logged before timeout
    if (msg in alert_history) and (
        alert_history[msg] + REPEATED_ALERT_TIMEOUT > datetime.now()
    ):
        return
    alert_history[msg] = datetime.now()
    print(f"*ALERT* {msg}")
 
 
def detect_malicious_ip(pkt):
    """
    Detection 1.1
    Detect communication with known malicious IPs.
    """
    # Retrieve Source and Destination IPs
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
 
    if ip_src in MALICIOUS_IPS:
        alert(f"Communication between malicious IP {ip_src} and {ip_dst}!")
    elif ip_dst in MALICIOUS_IPS:
        alert(f"Communication between malicious IP {ip_dst} and {ip_src}!")
 
def detect_malicious_dns(pkt):
    """
    Detection 1.2
    Detect DNS resolving of known malicious domains.
    """
    dns_query = pkt[DNSQR].qname.decode().strip(".")
 
    # Check for malicious domains in DNS Query, and alert if present
    if dns_query in MALICIOUS_DOMAINS:
        alert(f"DNS query for malicious domain '{dns_query}' from {pkt[IP].src}")
 
def track_stream(pkt):
    """
    Detection 1.3
    Helper function to track the TCP stream to reconstruct downloaded file
    """
    streamid = f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}"
 
    if streamid in tcp_streams:
        tcp_streams[streamid].append(pkt)
    else:
        tcp_streams[streamid] = []
        tcp_streams[streamid].append(pkt)
 
    # Check for RST or FIN flags that indicate the end of stream
    if 'R' in pkt[TCP].flags or 'F' in pkt[TCP].flags:
        full_data = extract_stream_data(tcp_streams[streamid])
        sha_1 = hashlib.sha1()
        sha_1.update(full_data)
        if sha_1.hexdigest() in MALICIOUS_HASHES.keys():
            alert(f"Malware detected in HTTP download! Client: {pkt[IP].dst}; Server: {pkt[IP].src}; Hash: {sha_1.hexdigest()} ({MALICIOUS_HASHES[sha_1.hexdigest()]})")
 
        del tcp_streams[streamid]
 
def extract_stream_data(packets):
    """
    Detection 1.3
    Helper function to reassemble TCP stream based on sequence number and extract the data
    """
    tcp_segments = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            tcp_segments.append(payload)
 
    stream_data = b''.join(tcp_segments)
 
    if b'\r\n\r\n' in stream_data:
        http_body = stream_data.split(b"\r\n\r\n")[1]
        return http_body
 
def detect_malicious_traffic(packet):
    """
    function to detect malicious network activity
    """
    try:
        if packet.haslayer(IP):
            detect_malicious_ip(packet)

        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            detect_malicious_dns(packet)

        if packet.haslayer(TCP) and packet.sport == 80:
            track_stream(packet)

        # --- TCP SYN Scan Detection ---
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Only consider SYN packets (common in TCP scans)
            if packet[TCP].flags == "S":
                if tcp_threshold.is_exceeded(packet):
                    alert(f"TCP scan detected from {packet[IP].src} to {packet[IP].dst}")

        # --- ARP Scan Detection ---
        if packet.haslayer(ARP):
            if arp_threshold.is_exceeded(packet):
                alert(f"ARP scan detected from {packet[Ether].src}")
            
    except Exception as e:
        print(f"Error: {e}")


def main():
    print("Starting NIDS!")
    network_interface = get_interface()
    print(f"Sniffing on interface: {network_interface}")
    sniff(filter="ip or arp", prn=detect_malicious_traffic, iface=network_interface)

if __name__ == "__main__":
    main()