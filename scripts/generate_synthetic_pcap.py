"""
Synthetic PCAP Generator for IRONCLAD Testing and Verification.

Generates realistic network captures containing:
1. Normal benign web traffic (HTTP, DNS)
2. Asymmetric TCP SYN port scanning sweep
3. High-entropy payload exfiltration on an uncommon port
"""

import os
from pathlib import Path
import random
import time

from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap


def generate_test_pcap(output_path: str = "data/sample_traffic.pcap", packet_count: int = 120) -> str:
    packets = []
    base_time = time.time()
    current_time = base_time

    # 1. Benign Web & DNS Sessions
    client_ip = "192.168.1.50"
    dns_server = "192.168.1.1"
    web_server = "93.184.216.34"

    # DNS Query & Response
    dns_query = (
        IP(src=client_ip, dst=dns_server)
        / UDP(sport=54123, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    dns_query.time = current_time
    packets.append(dns_query)
    current_time += 0.015

    dns_resp = (
        IP(src=dns_server, dst=client_ip)
        / UDP(sport=53, dport=54123)
        / DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata=web_server))
    )
    dns_resp.time = current_time
    packets.append(dns_resp)
    current_time += 0.020

    # Normal HTTP Handshake and Low-Entropy Request
    http_sport = 49152
    # SYN
    p_syn = IP(src=client_ip, dst=web_server) / TCP(sport=http_sport, dport=80, flags="S", seq=1000)
    p_syn.time = current_time
    packets.append(p_syn)
    current_time += 0.012

    # SYN-ACK
    p_synack = IP(src=web_server, dst=client_ip) / TCP(sport=80, dport=http_sport, flags="SA", seq=2000, ack=1001)
    p_synack.time = current_time
    packets.append(p_synack)
    current_time += 0.010

    # ACK
    p_ack = IP(src=client_ip, dst=web_server) / TCP(sport=http_sport, dport=80, flags="A", seq=1001, ack=2001)
    p_ack.time = current_time
    packets.append(p_ack)
    current_time += 0.005

    # HTTP GET Request (Low entropy, plaintext)
    http_req = (
        IP(src=client_ip, dst=web_server)
        / TCP(sport=http_sport, dport=80, flags="PA", seq=1001, ack=2001)
        / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
    )
    http_req.time = current_time
    packets.append(http_req)
    current_time += 0.035

    # HTTP 200 OK Response
    http_resp = (
        IP(src=web_server, dst=client_ip)
        / TCP(sport=80, dport=http_sport, flags="PA", seq=2001, ack=1001 + len(http_req[Raw].load))
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body><h1>It Works!</h1></body></html>")
    )
    http_resp.time = current_time
    packets.append(http_resp)
    current_time += 0.050

    # 2. Port Scanning Traffic (Attacker sweeping multiple ports with SYN without ACK)
    attacker_ip = "10.0.0.99"
    victim_ip = "192.168.1.100"
    target_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]

    for port in target_ports:
        scan_pkt = IP(src=attacker_ip, dst=victim_ip) / TCP(
            sport=random.randint(40000, 60000), dport=port, flags="S", seq=random.randint(1000, 999999)
        )
        scan_pkt.time = current_time
        packets.append(scan_pkt)
        current_time += random.uniform(0.002, 0.008)

    # 3. High-Entropy Covert Channel / Exfiltration Simulation
    # Generate pseudorandom bytes with maximum Shannon entropy (~7.9+)
    covert_src = "192.168.1.88"
    covert_dst = "198.51.100.77"
    uncommon_port = 9443

    # Send multiple chunks of high entropy data
    for seq_offset in range(10):
        # 512 bytes of high-entropy cryptographic bytes
        crypto_payload = os.urandom(512)
        exfil_pkt = (
            IP(src=covert_src, dst=covert_dst)
            / TCP(sport=51200, dport=uncommon_port, flags="PA", seq=5000 + seq_offset * 512, ack=1)
            / Raw(load=crypto_payload)
        )
        exfil_pkt.time = current_time
        packets.append(exfil_pkt)
        current_time += random.uniform(0.010, 0.025)

    # Save to PCAP file
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    print(f"Generated synthetic PCAP with {len(packets)} packets at: {out.resolve()}")
    return str(out.resolve())


if __name__ == "__main__":
    generate_test_pcap()
