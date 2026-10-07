"""Data models used by NetSentinel."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


def _iso(dt):
    return dt.isoformat() if isinstance(dt, datetime) else dt

@dataclass
class Packet:
    timestamp: datetime = field(default_factory=datetime.now)
    src: str = ""
    dst: str = ""
    protocol: str = "UNKNOWN"
    length: int = 0
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    def get_src_ip(self): return self.src or "-"
    def get_dst_ip(self): return self.dst or "-"
    def get_protocol(self): return self.protocol or "UNKNOWN"

    def to_dict(self):
        return {"time": _iso(self.timestamp), "src": self.src, "dst": self.dst,
                "proto": self.protocol, "length": self.length,
                "src_port": self.src_port, "dst_port": self.dst_port}

@dataclass
class TrafficStats:
    total_packets: int = 0
    source_counts: Dict[str, int] = field(default_factory=dict)
    destination_counts: Dict[str, int] = field(default_factory=dict)
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    source_ports: Dict[str, int] = field(default_factory=dict)
    unique_sources: int = 0
    unique_destinations: int = 0
    most_active_source: Optional[str] = None
    most_contacted_destination: Optional[str] = None
    most_common_protocol: Optional[str] = None
    tcp_count: int = 0
    udp_count: int = 0
    dns_count: int = 0
    icmp_count: int = 0
    arp_count: int = 0
    avg_packet_length: float = 0.0
    active_hosts: int = 0
    packets_per_second: float = 0.0

    def to_dict(self):
        return self.__dict__.copy()

@dataclass
class Alert:
    rule_name: str
    severity: str
    evidence: str
    why_it_matters: str = ""
    possible_benign_explanations: List[str] = field(default_factory=list)
    suggested_investigation: List[str] = field(default_factory=list)

    def to_dict(self): return self.__dict__.copy()

@dataclass
class InvestigationScore:
    total_score: int = 0
    level: str = "Normal"
    summary: str = "No significant anomaly indicators detected."
    contributions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self): return self.__dict__.copy()
