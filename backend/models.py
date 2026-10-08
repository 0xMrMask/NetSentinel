"""
NetSentinel — Models
Data structures for the entire application.
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any


def ip_direction(src: str, dst: str) -> Optional[str]:
    """Classify traffic direction from private-vs-public address space.
    Returns 'outbound', 'inbound', 'internal', or None if not IP-parseable."""
    try:
        s = ipaddress.ip_address(src)
        d = ipaddress.ip_address(dst)
    except ValueError:
        return None
    if s.is_private and not d.is_private:
        return "outbound"
    if not s.is_private and d.is_private:
        return "inbound"
    return "internal"


@dataclass
class Packet:
    """Represents a parsed network packet."""
    timestamp: datetime
    source: str
    destination: str
    protocol: str
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    interface: Optional[str] = None
    direction: Optional[str] = None
    raw_info: str = ""
    src_is_ip: bool = True
    dst_is_ip: bool = True

    def get_src_ip(self) -> str:
        return self.source

    def get_dst_ip(self) -> str:
        return self.destination

    def get_protocol(self) -> str:
        return self.protocol.upper()


@dataclass
class DetectionRule:
    """Represents a detection rule configuration."""
    name: str
    description: str
    severity: str
    threshold: int
    window_seconds: int

    def __post_init__(self):
        if self.severity not in ("Informational", "Low", "Medium", "High"):
            raise ValueError(f"Invalid severity: {self.severity}")


@dataclass
class Alert:
    """Represents a single detection alert."""
    rule_name: str
    severity: str
    timestamp: datetime
    source: str
    destination: Optional[str]
    observed_activity: str
    time_window: int
    threshold: int
    evidence: str
    why_it_matters: str
    possible_benign_explanations: List[str]
    suggested_investigation: List[str]
    investigation_score_contribution: int = 0
    confidence: int = 0
    mitre_technique: str = ""
    windows_matched: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "destination": self.destination,
            "observed_activity": self.observed_activity,
            "time_window": self.time_window,
            "threshold": self.threshold,
            "evidence": self.evidence,
            "why_it_matters": self.why_it_matters,
            "possible_benign_explanations": self.possible_benign_explanations,
            "suggested_investigation": self.suggested_investigation,
            "investigation_score_contribution": self.investigation_score_contribution,
            "confidence": self.confidence,
            "mitre_technique": self.mitre_technique,
            "windows_matched": self.windows_matched,
        }


@dataclass
class TrafficStats:
    """Aggregated traffic statistics."""
    total_packets: int = 0
    packets_per_second: float = 0.0
    total_bytes: int = 0
    bytes_per_second: float = 0.0
    duration_seconds: float = 0.0
    unique_sources: int = 0
    unique_destinations: int = 0
    active_hosts: int = 0
    most_active_source: Optional[str] = None
    most_contacted_destination: Optional[str] = None
    most_common_protocol: Optional[str] = None
    avg_packet_length: Optional[float] = None
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    source_counts: Dict[str, int] = field(default_factory=dict)
    destination_counts: Dict[str, int] = field(default_factory=dict)
    source_ports: Dict[str, int] = field(default_factory=dict)
    dns_count: int = 0
    icmp_count: int = 0
    arp_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    alerts: List[Alert] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "packets_per_second": round(self.packets_per_second, 1),
            "total_bytes": self.total_bytes,
            "bytes_per_second": round(self.bytes_per_second, 2),
            "duration_seconds": round(self.duration_seconds, 1),
            "unique_sources": self.unique_sources,
            "unique_destinations": self.unique_destinations,
            "active_hosts": self.active_hosts,
            "most_active_source": self.most_active_source,
            "most_contacted_destination": self.most_contacted_destination,
            "most_common_protocol": self.most_common_protocol,
            "avg_packet_length": round(self.avg_packet_length, 1) if self.avg_packet_length else None,
            "protocol_counts": self.protocol_counts,
            "source_counts": self.source_counts,
            "destination_counts": self.destination_counts,
            "source_ports": self.source_ports,
            "dns_count": self.dns_count,
            "icmp_count": self.icmp_count,
            "arp_count": self.arp_count,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
        }


@dataclass
class InvestigationScore:
    """Explainable investigation priority score (NOT probability of attack)."""
    total_score: int = 0
    contributions: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, label: str, score: int, reason: str):
        self.total_score += score
        self.contributions.append({
            "label": label,
            "score": score,
            "reason": reason,
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_score": self.total_score,
            "contributions": self.contributions,
        }


@dataclass
class CsvAnalysisResult:
    """Result of offline CSV analysis."""
    filename: str
    packets_loaded: int
    parsing_status: str
    missing_fields: List[str]
    unique_sources: int
    unique_destinations: int
    protocol_distribution: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    alerts: List[Alert]
    investigation_score: InvestigationScore
    demo_label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "packets_loaded": self.packets_loaded,
            "parsing_status": self.parsing_status,
            "missing_fields": self.missing_fields,
            "unique_sources": self.unique_sources,
            "unique_destinations": self.unique_destinations,
            "protocol_distribution": self.protocol_distribution,
            "top_sources": self.top_sources,
            "top_destinations": self.top_destinations,
            "alerts": [a.to_dict() for a in self.alerts],
            "investigation_score": self.investigation_score.to_dict(),
        }
