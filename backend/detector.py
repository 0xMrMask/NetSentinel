"""Explainable heuristic detection for educational network analysis."""
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List
from models import Alert, InvestigationScore, Packet

DEFAULT_THRESHOLDS = {
    "packets_per_source": 50, "unique_destinations": 10, "unique_ports": 10,
    "icmp_threshold": 30, "dns_threshold": 30, "repeated_communication": 40,
    "syn_threshold": 30, "traffic_spike_multiplier": 5, "time_window": 30,
}

class DetectionEngine:
    def __init__(self, thresholds=None, window_seconds=30):
        self.thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.window_seconds = window_seconds

    def detect(self, packets: List[Packet], now: datetime):
        alerts=[]
        if not packets: return alerts
        src=Counter(p.get_src_ip() for p in packets)
        dst_by_src=defaultdict(set); ports_by_src=defaultdict(set)
        proto=Counter(p.get_protocol() for p in packets)
        icmp=0; dns=0; syn=0; pairs=Counter()
        for p in packets:
            s,d=p.get_src_ip(),p.get_dst_ip()
            dst_by_src[s].add(d)
            if p.dst_port: ports_by_src[s].add(p.dst_port)
            pairs[(s,d)] += 1
            if p.get_protocol() == "ICMP": icmp += 1
            if p.get_protocol() == "DNS": dns += 1
            if p.get_protocol() == "TCP" and p.dst_port and getattr(p, "tcp_flags", "") == "S": syn += 1
        for s,c in src.items():
            if c >= self.thresholds["packets_per_source"]:
                alerts.append(Alert("High source packet volume","Medium",f"{s} generated {c} packets.","A single host is responsible for unusually high traffic volume.",["Normal download/upload activity","Software updates or backups"],["Check the host's active processes and connections","Compare the rate with normal baseline traffic"]))
            if len(dst_by_src[s]) >= self.thresholds["unique_destinations"]:
                alerts.append(Alert("Wide destination spread","Low",f"{s} contacted {len(dst_by_src[s])} unique destinations.","A host communicating with many destinations can indicate scanning or normal web/cloud activity.",["Browser or cloud-service traffic","Security software updates"],["Inspect destination domains/IP reputation","Check whether the destinations are expected"]))
            if len(ports_by_src[s]) >= self.thresholds["unique_ports"]:
                alerts.append(Alert("Multiple destination ports","Medium",f"{s} used {len(ports_by_src[s])} destination ports.","Many ports may indicate service discovery or diverse legitimate application traffic.",["Normal multi-service workstation","Development/testing activity"],["Review the individual ports and destinations","Correlate with process-level network connections"]))
        if icmp >= self.thresholds["icmp_threshold"]:
            alerts.append(Alert("High ICMP volume","Medium",f"{icmp} ICMP packets observed.","High ICMP volume can be consistent with discovery, diagnostics, or tunneling.",["Ping tests","Network troubleshooting"],["Inspect ICMP endpoints and timing","Determine whether traffic is expected"]))
        if dns >= self.thresholds["dns_threshold"]:
            alerts.append(Alert("High DNS volume","Low",f"{dns} DNS packets observed.","High DNS activity may be normal but can also merit investigation when paired with other anomalies.",["Busy browser","Endpoint security or telemetry"],["Review queried domains","Look for unusual periodicity or high-entropy names"]))
        for (s,d),c in pairs.items():
            if c >= self.thresholds["repeated_communication"]:
                alerts.append(Alert("Repeated communication","Low",f"{s} communicated with {d} {c} times.","Persistent communication may be normal or may indicate a long-lived service/channel.",["Streaming","Web/API sessions"],["Identify the destination service","Check timing and process ownership"]))
        if syn >= self.thresholds["syn_threshold"]:
            alerts.append(Alert("High TCP SYN activity","High",f"At least {syn} SYN packets observed.","A large SYN count can be associated with connection bursts or scanning.",["Application startup","Load testing"],["Review source/destination distribution","Check whether many connections failed"]))
        return alerts

    def compute_investigation_score(self, packets, now):
        alerts=self.detect(packets,now)
        weights={"Low":5,"Medium":15,"High":25,"Critical":35}
        contrib=[]; total=0
        seen=set()
        for a in alerts:
            if a.rule_name in seen: continue
            seen.add(a.rule_name); score=weights.get(a.severity,10); total+=score
            contrib.append({"label":a.rule_name,"score":score,"reason":a.evidence})
        total=min(100,total)
        level="Elevated" if total>=60 else "Watch" if total>=30 else "Normal"
        summary={"Normal":"Traffic does not currently show strong anomaly indicators.","Watch":"Some traffic patterns deserve a closer look.","Elevated":"Multiple anomaly indicators are present; investigate the evidence before drawing conclusions."}[level]
        return InvestigationScore(total,level,summary,contrib)
