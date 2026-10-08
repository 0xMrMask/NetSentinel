"""
Generate a sample Wireshark-style CSV for testing NetSentinel offline analysis.
Writes samples/sample_scan.csv with traffic designed to trigger several rules.
"""
import os
import random
from datetime import datetime, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "samples", "sample_scan.csv")

HEADER = "source,destination,protocol,length,src_port,dst_port,tcp_flags\n"

def main():
    rows = []
    t0 = datetime.now()

    # 1) Port scan: one host probes 15 destinations (triggers
    #    rule_host_scanning) and sweeps 12 ports on one target
    #    (triggers rule_port_scanning, threshold: >10 unique ports/dest)
    scanner = "192.168.1.100"
    for i in range(1, 16):
        for port in (22, 80, 443):
            rows.append(f'{scanner},10.0.0.{i},TCP,60,{random.randint(40000,60000)},{port},SYN')
    for port in range(20, 32):  # 12-port sweep on a single target
        rows.append(f'{scanner},10.0.0.99,TCP,60,{random.randint(40000,60000)},{port},SYN')

    # 2) ICMP burst: 40 ICMP packets from one source (triggers rule_high_icmp)
    for _ in range(40):
        rows.append("192.168.1.50,8.8.8.8,ICMP,98,,, ")

    # 3) Repeated communication: many packets one src->dst (triggers
    #    rule_repeated_communication)
    for _ in range(50):
        rows.append("192.168.1.20,192.168.1.1,TCP,150,51000,445,ACK")

    # 4) Normal background traffic
    protos = ["TCP", "UDP", "DNS", "HTTP"]
    for i in range(60):
        src = f"192.168.1.{random.randint(10, 40)}"
        dst = f"93.184.216.{random.randint(1, 254)}"
        proto = random.choice(protos)
        rows.append(f"{src},{dst},{proto},{random.randint(60, 1500)},{random.randint(40000,65000)},{random.choice([53,80,443])},")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="") as f:
        f.write(HEADER)
        f.write("\n".join(rows) + "\n")

    print(f"Wrote {len(rows)} rows to {OUT}")

if __name__ == "__main__":
    main()
