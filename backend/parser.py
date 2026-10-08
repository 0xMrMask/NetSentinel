"""
NetSentinel — Wireshark CSV Parser
Parses Wireshark export CSVs into structured packet data.
"""

import csv
from datetime import datetime
from typing import List, Dict, Any, Optional
from models import Packet, ip_direction


# Field name mappings for Wireshark CSV variations
FIELD_ALIASES = {
    "source": ["source", "source ip", "src", "ip.src", "ip.src_host", "ipv4.src_addr"],
    "destination": ["destination", "dest", "dst", "ip.dst", "ip.dst_host", "ipv4.dst_addr"],
    "protocol": ["protocol", "proto", "frame.protocols", "tcp", "udp", "icmp"],
    "length": ["length", "len", "frame.len", "ip.len"],
    "info": ["info", "details", "http.request.uri", "tcp.payload"],
    "src_port": ["src_port", "src.port", "srcport", "source_port", "source port", "tcp.srcport", "udp.srcport"],
    "dst_port": ["dst_port", "dst.port", "dstport", "dest_port", "dest port", "destination port", "tcp.dstport", "udp.dstport"],
    "tcp_flags": ["tcp_flags", "tcp.flags", "tcp.flags.syn", "tcp.flags.ack", "flags"],
    "src_mac": ["src_mac", "src mac", "eth.src", "eth.source", "sll.src.eth", "arp.src.hw_mac"],
    "dst_mac": ["dst_mac", "dst mac", "eth.dst", "eth.destination", "sll.dst.eth", "arp.dst.hw_mac"],
    "time": ["time", "frame.time", "ts", "unixtime"],
}


def _find_field(columns: List[str], alias_list: List[str]) -> Optional[str]:
    """Find a column in CSV headers, checking aliases."""
    for col in columns:
        col_lower = col.strip().lower()
        for alias in alias_list:
            if col_lower == alias.strip().lower():
                return col
    return None


def _parse_timestamp(value: str) -> datetime:
    """Try to parse common timestamp formats from Wireshark CSV."""
    value = value.strip()
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pass
    try:
        return datetime.fromtimestamp(float(value))
    except (ValueError, OSError):
        pass
    return datetime.now()


def parse_csv(filepath: str) -> Dict[str, Any]:
    """
    Parse a Wireshark CSV file and return structured data.
    Returns dict with packets, missing_fields, parsing_status, etc.
    """
    result = {
        "packets": [],
        "missing_fields": [],
        "parsing_status": "OK",
        "warnings": [],
        "field_map": {},
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            columns = reader.fieldnames or []

            # Detect required fields
            source_col = _find_field(columns, FIELD_ALIASES["source"])
            dest_col = _find_field(columns, FIELD_ALIASES["destination"])
            proto_col = _find_field(columns, FIELD_ALIASES["protocol"])
            length_col = _find_field(columns, FIELD_ALIASES["length"])
            info_col = _find_field(columns, FIELD_ALIASES["info"])
            src_port_col = _find_field(columns, FIELD_ALIASES["src_port"])
            dst_port_col = _find_field(columns, FIELD_ALIASES["dst_port"])
            flags_col = _find_field(columns, FIELD_ALIASES["tcp_flags"])
            src_mac_col = _find_field(columns, FIELD_ALIASES["src_mac"])
            dst_mac_col = _find_field(columns, FIELD_ALIASES["dst_mac"])
            time_col = _find_field(columns, FIELD_ALIASES["time"])

            # Collect missing fields
            missing = []
            if not source_col:
                missing.append("Source IP")
            if not dest_col:
                missing.append("Destination IP")
            if not proto_col:
                missing.append("Protocol")

            result["missing_fields"] = missing

            if not source_col or not dest_col:
                result["parsing_status"] = "ERROR"
                result["warnings"].append("CSV does not contain required Source/Destination columns")
                return result

            if not proto_col:
                result["parsing_status"] = "ERROR"
                result["warnings"].append("CSV does not contain a Protocol column")
                return result

            # Parse packets
            packets = []
            for row_num, row in enumerate(reader, start=2):
                try:
                    source = row.get(source_col, "").strip()
                    destination = row.get(dest_col, "").strip()
                    protocol = row.get(proto_col, "").strip().upper()

                    length_str = row.get(length_col, "0").strip()
                    try:
                        length = int(length_str)
                    except ValueError:
                        length = 0

                    src_port = None
                    if src_port_col:
                        try:
                            src_port = int(row.get(src_port_col, "0").strip())
                        except ValueError:
                            src_port = None

                    dst_port = None
                    if dst_port_col:
                        try:
                            dst_port = int(row.get(dst_port_col, "0").strip())
                        except ValueError:
                            dst_port = None

                    flags = None
                    if flags_col and row.get(flags_col):
                        flags = row.get(flags_col, "").strip()

                    src_mac = None
                    if src_mac_col and row.get(src_mac_col):
                        src_mac = row.get(src_mac_col, "").strip() or None

                    dst_mac = None
                    if dst_mac_col and row.get(dst_mac_col):
                        dst_mac = row.get(dst_mac_col, "").strip() or None

                    timestamp = datetime.now()
                    if time_col:
                        timestamp = _parse_timestamp(row.get(time_col, ""))

                    packets.append(Packet(
                        timestamp=timestamp,
                        source=source,
                        destination=destination,
                        protocol=protocol,
                        length=length,
                        src_port=src_port,
                        dst_port=dst_port,
                        tcp_flags=flags,
                        src_mac=src_mac,
                        dst_mac=dst_mac,
                        direction=ip_direction(source, destination),
                        raw_info=row.get(info_col, ""),
                    ))
                except Exception:
                    result["warnings"].append(f"Row {row_num}: parse error")

            result["packets"] = packets
            result["parsing_status"] = "OK" if packets else "EMPTY"

    except UnicodeDecodeError:
        result["parsing_status"] = "ERROR"
        result["warnings"].append("Could not read the file as UTF-8 text")
    except FileNotFoundError:
        result["parsing_status"] = "ERROR"
        result["warnings"].append("File not found")
    except Exception as e:
        result["parsing_status"] = "ERROR"
        result["warnings"].append(f"Parsing error: {str(e)}")

    return result
