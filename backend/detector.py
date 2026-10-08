"""
NetSentinel — Detection Engine
Rule-based detection for network traffic anomalies.
Everything is local. No external APIs.

Detection runs inside real time windows:
  * detect_recent() — live dashboard path: rules evaluate only the packets
    inside the current window, so "50 packets in 30 seconds" means something
    different from "50 packets in 30 minutes".
  * detect() — analysis/report path: the whole capture is sliced into
    consecutive windows, rules run per window and alerts are merged
    (with a windows_matched counter).
Traffic-spike detection always compares the recent window against the
longer-term baseline rate, so it needs the full packet set.
"""

from datetime import datetime, timedelta
from typing import List, Tuple
from collections import defaultdict
from models import Alert, InvestigationScore
from config import DETECTION_CONFIG

# Backward-compatible alias (kept so existing imports keep working)
DEFAULT_THRESHOLDS = DETECTION_CONFIG

DEFAULT_SEVERITIES = {
    "high_packet_volume": "Medium",
    "host_scanning": "Medium",
    "port_scanning": "High",
    "high_icmp": "Medium",
    "high_dns": "Low",
    "repeated_communication": "Low",
    "tcp_syn": "Medium",
    "traffic_spike": "High",
    "arp_spoofing": "High",
}

# MITRE ATT&CK mappings shown in alerts and reports
MITRE_TECHNIQUES = {
    "HIGH PACKET VOLUME": "",
    "POSSIBLE NETWORK SCANNING": "T1018 — Remote System Discovery",
    "PORT SCAN DETECTED": "T1046 — Network Service Scanning",
    "HIGH ICMP TRAFFIC": "T1018 — Remote System Discovery",
    "HIGH DNS TRAFFIC": "T1071.004 — Application Layer Protocol: DNS",
    "REPEATED COMMUNICATION": "T1071 — Application Layer Protocol",
    "TCP SYN ACTIVITY": "T1498 — Network Denial of Service",
    "SUDDEN TRAFFIC SPIKE": "",
    "ARP SPOOFING DETECTED": "T1557.002 — Adversary-in-the-Middle: ARP Spoofing",
}


def _tcp_flag_set(flags) -> set:
    """
    Parse a TCP flags string into a set of short flag letters.
    Handles both Scapy style ('S', 'SA', 'R') and Wireshark style
    ('SYN', 'SYN ACK', 'RST').
    """
    if not flags:
        return set()
    s = str(flags).upper()
    out = set()
    for name, short in (("SYN", "S"), ("ACK", "A"), ("RST", "R"),
                        ("FIN", "F"), ("PSH", "P"), ("URG", "U")):
        if name in s:
            out.add(short)
            s = s.replace(name, "")
    for ch in s:
        if ch in "SA RFPU":
            out.add(ch)
    return out


class DetectionEngine:
    """Main detection engine. Runs rules over a list of packets."""

    def __init__(self, thresholds: dict = None, window_seconds: int = 30):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS
        self.window_seconds = window_seconds

    # ---- Time-window helpers ----
    def _get_window(self, now: datetime) -> timedelta:
        return timedelta(seconds=self.window_seconds)

    def _get_window_start(self, now: datetime) -> datetime:
        return now - self._get_window(now)

    def _recent_packets(self, packets: List, now: datetime) -> List:
        """Packets inside the current time window, relative to `now`."""
        cutoff = now - self._get_window(now)
        return [p for p in packets if p.timestamp >= cutoff]

    def _window_slices(self, packets: List) -> List[Tuple[List, datetime]]:
        """
        Split a capture into consecutive window_seconds slices.
        Returns [(packets_in_slice, reference_time), ...].
        Short captures come back as a single slice.
        """
        if not packets:
            return []
        ordered = sorted(packets, key=lambda p: p.timestamp)
        span = (ordered[-1].timestamp - ordered[0].timestamp).total_seconds()
        if span <= self.window_seconds:
            return [(ordered, ordered[-1].timestamp)]

        slices = []
        start = ordered[0].timestamp
        chunk: List = []
        for p in ordered:
            if (p.timestamp - start).total_seconds() >= self.window_seconds:
                if chunk:
                    slices.append((chunk, chunk[-1].timestamp))
                start = p.timestamp
                chunk = []
            chunk.append(p)
        if chunk:
            slices.append((chunk, chunk[-1].timestamp))
        return slices


    # ---- Rule 1: High Packet Volume ----
    def rule_high_packet_volume(self, packets: List, now: datetime) -> List[Alert]:
        alerts = []
        source_counts = defaultdict(int)
        for p in packets:
            source_counts[p.get_src_ip()] += 1

        threshold = self.thresholds["packets_per_source"]
        for src, count in source_counts.items():
            if count > threshold:
                alerts.append(Alert(
                    rule_name="HIGH PACKET VOLUME",
                    severity=DEFAULT_SEVERITIES["high_packet_volume"],
                    timestamp=now,
                    source=src,
                    destination=None,
                    observed_activity=f"{count} packets in window",
                    time_window=self.window_seconds,
                    threshold=threshold,
                    evidence=f"Source {src} sent {count} packets during the {self.window_seconds}s window (threshold: {threshold}).",
                    why_it_matters="A high packet volume can indicate a file transfer, software update, backup, network scan, automated script, or abnormal traffic. Investigate to determine the cause.",
                    possible_benign_explanations=[
                        "Legitimate file transfer",
                        "Software update",
                        "Automated backup",
                        "Network monitoring",
                        "Misconfigured device",
                        "Automated script",
                        "Malicious activity",
                    ],
                    suggested_investigation=[
                        "Identify the source device",
                        "Check what applications are running",
                        "Review recent network activity",
                        "Check for large file transfers",
                        "Verify if this is an authorised backup task",
                        "Correlate with endpoint logs",
                    ],
                    investigation_score_contribution=20,
                ))
        return alerts


    # ---- Rule 2: Host Scanning ----
    def rule_host_scanning(self, packets: List, now: datetime) -> List[Alert]:
        alerts = []
        src_dest_counts = defaultdict(set)
        for p in packets:
            src_dest_counts[p.get_src_ip()].add(p.get_dst_ip())

        threshold = self.thresholds["unique_destinations"]
        for src, dests in src_dest_counts.items():
            if len(dests) > threshold:
                alerts.append(Alert(
                    rule_name="POSSIBLE NETWORK SCANNING",
                    severity=DEFAULT_SEVERITIES["host_scanning"],
                    timestamp=now,
                    source=src,
                    destination=None,
                    observed_activity=f"Communicating with {len(dests)} unique destinations",
                    time_window=self.window_seconds,
                    threshold=threshold,
                    evidence=f"Source {src} contacted {len(dests)} unique destinations in {self.window_seconds}s (threshold: {threshold}).",
                    why_it_matters="Scanning many destinations can be asset discovery, network management, vulnerability scanning, or malicious network discovery. Investigate to determine the purpose.",
                    possible_benign_explanations=[
                        "Asset discovery",
                        "Network management",
                        "Monitoring software",
                        "Vulnerability scanning",
                        "Legitimate administrative tool",
                        "Malicious network scanning",
                    ],
                    suggested_investigation=[
                        "Identify the source device",
                        "Check device management software",
                        "Review destination IP addresses",
                        "Look for port scanning patterns",
                        "Check if it is an authorised scanner",
                        "Correlate with endpoint logs",
                    ],
                    investigation_score_contribution=15,
                    confidence=60,
                    mitre_technique=MITRE_TECHNIQUES["POSSIBLE NETWORK SCANNING"],
                ))
        return alerts


    # ---- Rule 3: Port Scanning (with SYN/ACK ratio) ----
    def rule_port_scanning(self, packets: List, now: datetime) -> List[Alert]:
        """
        A real port scan looks like: one source hits many ports on one
        target inside a short window, mostly SYNs, with few (if any)
        established ACK sessions.
        """
        alerts = []
        ports_by_pair = defaultdict(set)
        syn_by_pair = defaultdict(int)
        ack_by_pair = defaultdict(int)
        first_last = {}

        for p in packets:
            if p.dst_port is None:
                continue
            pair = (p.get_src_ip(), p.get_dst_ip())
            ports_by_pair[pair].add(p.dst_port)

            span_pair = first_last.get(pair)
            if span_pair is None:
                first_last[pair] = [p.timestamp, p.timestamp]
            else:
                span_pair[1] = p.timestamp

            if p.get_protocol() == "TCP":
                flags = _tcp_flag_set(p.tcp_flags)
                if "S" in flags and "A" not in flags:
                    syn_by_pair[pair] += 1
                elif "A" in flags and "S" not in flags:
                    ack_by_pair[pair] += 1

        threshold = self.thresholds["unique_ports"]
        for (src, dst), ports in ports_by_pair.items():
            if len(ports) <= threshold:
                continue

            syn = syn_by_pair[(src, dst)]
            ack = ack_by_pair[(src, dst)]
            # Many SYNs, barely any completed handshakes = scan signature
            syn_dominant = syn >= 5 and syn > ack * 2
            confidence = 90 if syn_dominant else 70

            ports_sorted = sorted(ports)
            shown = ", ".join(str(x) for x in ports_sorted[:12])
            if len(ports_sorted) > 12:
                shown += f", +{len(ports_sorted) - 12} more"

            span = 0.0
            span_pair = first_last.get((src, dst))
            if span_pair is not None:
                span = max(0.0, (span_pair[1] - span_pair[0]).total_seconds())

            alerts.append(Alert(
                rule_name="PORT SCAN DETECTED",
                severity=DEFAULT_SEVERITIES["port_scanning"],
                timestamp=now,
                source=src,
                destination=dst,
                observed_activity=f"{len(ports)} unique ports · {syn} SYN / {ack} ACK",
                time_window=self.window_seconds,
                threshold=threshold,
                evidence=(f"Source {src} targeted {len(ports)} unique ports on {dst} "
                          f"({shown}) over {span:.1f}s — {syn} SYN vs {ack} ACK "
                          f"(threshold: {threshold} ports)."),
                why_it_matters="Multiple port scans can indicate systematic probing for open services, vulnerability scanning, or attempts to find exploitable services. Investigate and document findings.",
                possible_benign_explanations=[
                    "Service discovery",
                    "Automated deployment",
                    "Network inventory scanning",
                    "Load balancer health checks",
                    "Security auditing tool",
                ],
                suggested_investigation=[
                    "Identify the source device",
                    "Review the destination ports",
                    "Check for port scanning patterns",
                    "Verify if the destination services are expected",
                    "Check firewall logs",
                    "Look for SYN flood patterns",
                ],
                investigation_score_contribution=30 if syn_dominant else 20,
                confidence=confidence,
                mitre_technique=MITRE_TECHNIQUES["PORT SCAN DETECTED"],
            ))
        return alerts


    # ---- Rule 4: High ICMP ----
    def rule_high_icmp(self, packets: List, now: datetime) -> List[Alert]:
        alerts = []
        src_icmp_counts = defaultdict(int)
        for p in packets:
            if p.get_protocol() == "ICMP":
                src_icmp_counts[p.get_src_ip()] += 1

        threshold = self.thresholds["icmp_threshold"]
        for src, count in src_icmp_counts.items():
            if count > threshold:
                alerts.append(Alert(
                    rule_name="HIGH ICMP TRAFFIC",
                    severity=DEFAULT_SEVERITIES["high_icmp"],
                    timestamp=now,
                    source=src,
                    destination=None,
                    observed_activity=f"{count} ICMP packets",
                    time_window=self.window_seconds,
                    threshold=threshold,
                    evidence=f"Source {src} sent {count} ICMP packets in {self.window_seconds}s (threshold: {threshold}).",
                    why_it_matters="ICMP is used for troubleshooting, monitoring, ping sweeps, and network discovery. High activity can be benign or indicate scanning.",
                    possible_benign_explanations=[
                        "Network troubleshooting",
                        "Monitoring tool",
                        "Ping sweep",
                        "Network discovery",
                        "Misconfigured device",
                        "Malicious activity",
                    ],
                    suggested_investigation=[
                        "Identify the source device",
                        "Check if it is a monitoring tool",
                        "Review ICMP destination addresses",
                        "Look for ping sweep patterns",
                        "Check firewall logs",
                        "Verify authorised network scans",
                    ],
                    investigation_score_contribution=15,
                    confidence=60,
                    mitre_technique=MITRE_TECHNIQUES["HIGH ICMP TRAFFIC"],
                ))
        return alerts


    # ---- Rule 5: High DNS ----
    def rule_high_dns(self, packets: List, now: datetime) -> List[Alert]:
        alerts = []
        src_dns_counts = defaultdict(int)
        for p in packets:
            if p.get_protocol() == "DNS":
                src_dns_counts[p.get_src_ip()] += 1

        threshold = self.thresholds["dns_threshold"]
        for src, count in src_dns_counts.items():
            if count > threshold:
                alerts.append(Alert(
                    rule_name="HIGH DNS QUERIES",
                    severity=DEFAULT_SEVERITIES["high_dns"],
                    timestamp=now,
                    source=src,
                    destination=None,
                    observed_activity=f"{count} DNS queries",
                    time_window=self.window_seconds,
                    threshold=threshold,
                    evidence=f"Source {src} sent {count} DNS queries in {self.window_seconds}s (threshold: {threshold}).",
                    why_it_matters="High DNS activity can indicate DNS tunneling, data exfiltration, subdomain scanning, or a compromised host querying many external domains.",
                    possible_benign_explanations=[
                        "Software update",
                        "CDN lookup",
                        "High volume of web requests",
                        "Internal DNS server querying external zones",
                        "Law of large numbers anomaly",
                    ],
                    suggested_investigation=[
                        "Identify the source device",
                        "Review the DNS destination addresses",
                        "Check for known malware domains",
                        "Look for DNS tunneling patterns",
                        "Verify legitimate service requirements",
                    ],
                    investigation_score_contribution=10,
                    confidence=50,
                    mitre_technique=MITRE_TECHNIQUES["HIGH DNS TRAFFIC"],
                ))
        return alerts




    # ---- Rule 6: Repeated Communication ----
    def rule_repeated_communication(self, packets: List, now: datetime) -> List[Alert]:
        alerts = []
        src_dst_counts = defaultdict(int)
        src_dst_ports = defaultdict(set)
        for p in packets:
            if p.dst_port is not None:
                key = (p.get_src_ip(), p.get_dst_ip())
                src_dst_counts[key] += 1
                src_dst_ports[key].add(p.dst_port)

        threshold = self.thresholds["repeated_communication"]
        for (src, dst), count in src_dst_counts.items():
            if count > threshold:
                alerts.append(Alert(
                    rule_name="REPEATED COMMUNICATION",
                    severity=DEFAULT_SEVERITIES["repeated_communication"],
                    timestamp=now,
                    source=src,
                    destination=dst,
                    observed_activity=f"{count} packets ({len(src_dst_ports[(src, dst)])} unique ports)",
                    time_window=self.window_seconds,
                    threshold=threshold,
                    evidence=f"Source {src} sent {count} packets to {dst} in {self.window_seconds}s (threshold: {threshold}).",
                    why_it_matters="Repeated communication with a single destination can indicate data exfiltration, command and control, or excessive application traffic.",
                    possible_benign_explanations=[
                        "Server synchronization",
                        "Database replication",
                        "Backup service",
                        "Log forwarding",
                        "Streaming service",
                    ],
                    suggested_investigation=[
                        "Identify the source device",
                        "Check the destination IP address",
                        "Review the data being transferred",
                        "Look at the time pattern",
                        "Check if it is an authorised service",
                        "Investigate if it is irregular for that pair",
                    ],
                    investigation_score_contribution=10,
                    confidence=40,
                    mitre_technique=MITRE_TECHNIQUES["REPEATED COMMUNICATION"],
                ))
        return alerts



    # ---- Rule 7: TCP SYN Activity ----
    def rule_tcp_syn(self, packets: List, now: datetime) -> List[Alert]:
        alerts = []
        src_syn_counts = defaultdict(int)
        for p in packets:
            if p.get_protocol() == "TCP" and "S" in _tcp_flag_set(p.tcp_flags) and "A" not in _tcp_flag_set(p.tcp_flags):
                src_syn_counts[p.get_src_ip()] += 1

        threshold = self.thresholds["syn_threshold"]
        for src, count in src_syn_counts.items():
            if count > threshold:
                alerts.append(Alert(
                    rule_name="TCP SYN ACTIVITY",
                    severity=DEFAULT_SEVERITIES["tcp_syn"],
                    timestamp=now,
                    source=src,
                    destination=None,
                    observed_activity=f"{count} SYN packets",
                    time_window=self.window_seconds,
                    threshold=threshold,
                    evidence=f"Source {src} sent {count} TCP SYN packets in {self.window_seconds}s (threshold: {threshold}).",
                    why_it_matters="SYN packets are used to start TCP connections. Many SYN packets can be normal connection attempts, a port scan, or a DoS-like pattern.",
                    possible_benign_explanations=[
                        "Normal connection attempts",
                        "Unavailable services",
                        "Load balancer health checks",
                    ],
                    suggested_investigation=[
                        "Identify the source device",
                        "Review destination ports",
                        "Check for port scanning patterns",
                        "Verify if the destination services are expected",
                        "Check firewall logs",
                        "Look for SYN flood patterns",
                    ],
                    investigation_score_contribution=10,
                    confidence=55,
                    mitre_technique=MITRE_TECHNIQUES["TCP SYN ACTIVITY"],
                ))
        return alerts



    # ---- Rule 8: Traffic Spike (baseline vs current rate) ----
    def rule_traffic_spike(self, packets: List, now: datetime) -> List[Alert]:
        """
        Compare the packet rate of the recent window against the longer
        baseline rate built from the packets before that window.
        Needs the full packet set (the baseline lives outside the window).
        """
        alerts = []
        if len(packets) < 30:
            return alerts

        timestamps = sorted(p.timestamp for p in packets)
        ref = timestamps[-1]
        window_start = ref - timedelta(seconds=self.window_seconds)
        recent = [t for t in timestamps if t >= window_start]
        baseline = [t for t in timestamps if t < window_start]

        if len(recent) < 10 or len(baseline) < 20:
            return alerts

        baseline_span = (baseline[-1] - baseline[0]).total_seconds()
        if baseline_span <= 0:
            return alerts

        current_rate = len(recent) / self.window_seconds
        baseline_rate = len(baseline) / baseline_span
        multiplier = self.thresholds["traffic_spike_multiplier"]

        if baseline_rate > 0 and current_rate > (baseline_rate * multiplier):
            ratio = current_rate / baseline_rate
            alerts.append(Alert(
                rule_name="SUDDEN TRAFFIC SPIKE",
                severity=DEFAULT_SEVERITIES["traffic_spike"],
                timestamp=now,
                source="SYSTEM",
                destination=None,
                observed_activity=f"{current_rate:.0f} pps now vs {baseline_rate:.0f} pps baseline",
                time_window=self.window_seconds,
                threshold=multiplier,
                evidence=(f"Packet rate rose from a {baseline_rate:.1f} pps baseline to "
                          f"{current_rate:.1f} pps ({ratio:.1f}× baseline) in the last "
                          f"{self.window_seconds}s — threshold is {multiplier}×."),
                why_it_matters="A sudden traffic spike can be a file transfer, backup, software update, streaming, scanning, or unusual application behaviour. Investigate to determine cause.",
                possible_benign_explanations=[
                    "File transfer",
                    "Backup job",
                    "Software update",
                    "Streaming media",
                    "Network broadcast storm",
                    "Automated traffic",
                    "Unusual application behaviour",
                ],
                suggested_investigation=[
                    "Check for large file transfers",
                    "Verify backup jobs are scheduled",
                    "Review recent software updates",
                    "Check for streaming activity",
                    "Look at source and destination IPs",
                    "Correlate with endpoint activity",
                ],
                investigation_score_contribution=25,
                confidence=70,
                mitre_technique=MITRE_TECHNIQUES["SUDDEN TRAFFIC SPIKE"],
            ))
        return alerts

    # ---- Rule 9: ARP Spoofing (IP → MAC conflict) ----
    def rule_arp_spoofing(self, packets: List, now: datetime) -> List[Alert]:
        """
        Classic MITM signature: the same IP address is announced by
        different MAC addresses inside the window (gratuitous ARP replies,
        gateway impersonation).
        """
        alerts = []
        ip_macs = defaultdict(set)
        for p in packets:
            if p.get_protocol() == "ARP" and p.src_mac:
                ip_macs[p.get_src_ip()].add(p.src_mac.lower())

        for ip, macs in ip_macs.items():
            if len(macs) >= 2:
                mac_list = ", ".join(sorted(macs))
                alerts.append(Alert(
                    rule_name="ARP SPOOFING DETECTED",
                    severity=DEFAULT_SEVERITIES["arp_spoofing"],
                    timestamp=now,
                    source=ip,
                    destination=None,
                    observed_activity=f"{len(macs)} MACs announce {ip}",
                    time_window=self.window_seconds,
                    threshold=1,
                    evidence=(f"IP {ip} was announced by {len(macs)} different MACs "
                              f"({mac_list}) within the {self.window_seconds}s window — "
                              f"a classic ARP spoofing / man-in-the-middle pattern."),
                    why_it_matters="If two MAC addresses claim the same IP, an attacker may be redirecting traffic through their machine (ARP spoofing) to intercept or modify traffic on the local network.",
                    possible_benign_explanations=[
                        "NIC failover / bonding",
                        "VM migration",
                        "Router redundancy (HSRP/VRRP)",
                        "Stale ARP cache during re-addressing",
                        "DHCP lease change",
                    ],
                    suggested_investigation=[
                        "Identify the MAC addresses (check the vendor prefix)",
                        "Compare with the legitimate gateway MAC",
                        "Check for duplicate IP configuration",
                        "Capture targeted ARP traffic to confirm",
                        "Enable dynamic ARP inspection on the switch if available",
                    ],
                    investigation_score_contribution=35,
                    confidence=85,
                    mitre_technique=MITRE_TECHNIQUES["ARP SPOOFING DETECTED"],
                ))
        return alerts


    # ---- Rule orchestration ----
    def _run_window_rules(self, packets: List, now: datetime) -> List[Alert]:
        """Run every rule that is meaningful inside one time window.
        (Traffic spike is excluded — it needs the full capture for a baseline.)"""
        if not packets:
            return []
        alerts = []
        alerts.extend(self.rule_high_packet_volume(packets, now))
        alerts.extend(self.rule_host_scanning(packets, now))
        alerts.extend(self.rule_port_scanning(packets, now))
        alerts.extend(self.rule_high_icmp(packets, now))
        alerts.extend(self.rule_high_dns(packets, now))
        alerts.extend(self.rule_repeated_communication(packets, now))
        alerts.extend(self.rule_tcp_syn(packets, now))
        alerts.extend(self.rule_arp_spoofing(packets, now))
        return alerts

    # ---- Main entry point ----
    def detect(self, packets: List, now: datetime) -> List[Alert]:
        """
        Full-capture analysis: run windowed rules over consecutive time
        windows, merge duplicate alerts (counting how many windows each one
        matched), then add the global traffic-spike check.
        """
        best = {}
        counts = defaultdict(int)

        for chunk, ref in self._window_slices(packets):
            for alert in self._run_window_rules(chunk, ref):
                key = (alert.rule_name, alert.source, alert.destination)
                counts[key] += 1
                if key not in best or (alert.investigation_score_contribution
                                       > best[key].investigation_score_contribution):
                    best[key] = alert

        for alert in self.rule_traffic_spike(packets, now):
            key = (alert.rule_name, alert.source, alert.destination)
            counts[key] += 1
            best[key] = alert

        for key, alert in best.items():
            alert.windows_matched = counts[key]
        return list(best.values())

    def detect_recent(self, packets: List, now: datetime) -> List[Alert]:
        """Live path: rules over the current time window only."""
        recent = self._recent_packets(packets, now)
        alerts = self._run_window_rules(recent, now)
        alerts.extend(self.rule_traffic_spike(packets, now))
        return alerts



    # ---- Compute investigation score ----
    def compute_investigation_score(self, packets: List, now: datetime) -> InvestigationScore:
        score = InvestigationScore()
        packet_counts = defaultdict(int)
        for p in packets:
            packet_counts[p.get_src_ip()] += 1

        threshold = self.thresholds["packets_per_source"]
        for src, count in packet_counts.items():
            if count > threshold:
                score.add("High packet volume", 20, f"{src} sent {count} packets")

        src_dest_counts = defaultdict(set)
        for p in packets:
            src_dest_counts[p.get_src_ip()].add(p.get_dst_ip())

        threshold_unique = self.thresholds["unique_destinations"]
        for src, dests in src_dest_counts.items():
            if len(dests) > threshold_unique:
                score.add("Many destinations", 15, f"{src} contacted {len(dests)} destinations")

        # Port-scan behaviour: many ports on one target
        ports_by_pair = defaultdict(set)
        for p in packets:
            if p.dst_port is not None:
                ports_by_pair[(p.get_src_ip(), p.get_dst_ip())].add(p.dst_port)
        threshold_ports = self.thresholds["unique_ports"]
        for (src, dst), ports in ports_by_pair.items():
            if len(ports) > threshold_ports:
                score.add("Port scan behaviour", 25,
                          f"{src} probed {len(ports)} ports on {dst}")

        # ARP anomalies: one IP claimed by several MACs
        ip_macs = defaultdict(set)
        for p in packets:
            if p.get_protocol() == "ARP" and p.src_mac:
                ip_macs[p.get_src_ip()].add(p.src_mac.lower())
        for ip, macs in ip_macs.items():
            if len(macs) > 1:
                score.add("ARP anomaly", 30,
                          f"{ip} was announced by {len(macs)} different MACs")

        icmp_counts = defaultdict(int)
        for p in packets:
            if p.get_protocol() == "ICMP":
                icmp_counts[p.get_src_ip()] += 1

        threshold_icmp = self.thresholds["icmp_threshold"]
        for src, count in icmp_counts.items():
            if count > threshold_icmp:
                score.add("High ICMP", 15, f"{src} sent {count} ICMP packets")

        dns_counts = defaultdict(int)
        for p in packets:
            if p.get_protocol() == "DNS":
                dns_counts[p.get_src_ip()] += 1

        threshold_dns = self.thresholds["dns_threshold"]
        for src, count in dns_counts.items():
            if count > threshold_dns:
                score.add("DNS spike", 10, f"{src} sent {count} DNS packets")

        return score
