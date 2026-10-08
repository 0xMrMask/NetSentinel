"""
NetSentinel — Packet Capture Engine
Captures packets from a local network interface using Scapy + Npcap.
Windows 11 friendly: pre-flight validation, responsive stop, error surfacing.
"""

import logging
import os
import sys
import threading
from datetime import datetime
from typing import Optional

from scapy.all import sniff, conf, Ether, IP, TCP, UDP, ICMP, ARP
from models import Packet, ip_direction

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("NetSentinel")

# IP protocol number -> name (for packets without a parsed L4 layer)
IP_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPV6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPV6", 89: "OSPF",
}


def npcap_installed() -> bool:
    """Check for Npcap/WinPcap DLLs on Windows. Always True on other OSes."""
    if sys.platform != "win32":
        return True
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    return any(
        os.path.exists(os.path.join(system32, dll))
        for dll in ("wpcap.dll", "packet.dll")
    )


def is_admin() -> bool:
    """True if running with elevated privileges (Windows)."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def resolve_interface(interface: str) -> str:
    """
    Map a friendly name (e.g. "Wi-Fi") to the device name sniff() expects
    (e.g. r'\\Device\\NPF_{...}'). Returns the input unchanged if already valid
    or if no match is found.
    """
    if interface in conf.ifaces:
        return interface
    for key, iface in conf.ifaces.items():
        if iface.name == interface or getattr(iface, "description", "") == interface:
            return str(key)
    return interface


class PacketCaptureEngine:
    """Captures packets from a network interface using Scapy+Npcap."""

    def __init__(self):
        self._running = False
        self._packet_count = 0
        self._bytes_captured = 0
        self._interface = None
        self._interface_label = None  # friendly name shown in the UI
        self._packet_callback = None
        self._thread: Optional[threading.Thread] = None
        self._started_at: Optional[datetime] = None
        self._stopped_at: Optional[datetime] = None
        self.last_error: Optional[str] = None

    def set_callback(self, callback):
        """Set a callback function for each captured packet."""
        self._packet_callback = callback

    def is_running(self) -> bool:
        return self._running

    def validate(self, interface: str) -> Optional[str]:
        """
        Synchronous pre-flight check: verifies Npcap, resolves the interface
        and performs a short dry-run sniff. Returns an error message or None.
        """
        if not interface:
            return "No interface specified"
        if sys.platform == "win32" and not npcap_installed():
            return ("Npcap is not installed. Install it from https://npcap.com "
                    "(tick 'Install in Admin-less Mode') and restart the server.")
        resolved = resolve_interface(interface)
        try:
            sniff(iface=resolved, filter="ip or arp", timeout=0.3, store=False)
        except Exception as e:
            return f"Cannot capture on '{interface}': {e}"
        return None

    def start_capture(self, interface: str, packet_filter: str = "ip or arp") -> bool:
        """
        Blocking capture loop (run it in a thread). Uses 1-second sniff chunks
        so stop_capture() takes effect within ~1s even with no traffic.
        Returns True when the loop exits cleanly, False on error.
        """
        self.last_error = None
        self._running = True
        self._packet_count = 0
        self._bytes_captured = 0
        self._started_at = datetime.now()
        self._stopped_at = None
        self._interface_label = interface
        self._interface = resolve_interface(interface)

        if sys.platform == "win32" and not is_admin():
            logger.warning("Not running as Administrator; capture may fail "
                           "unless Npcap was installed in Admin-less Mode.")

        try:
            while self._running:
                sniff(
                    iface=self._interface,
                    filter=packet_filter,
                    prn=self._handle_packet,
                    store=False,
                    timeout=1,
                )
            return True
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Capture error on {interface}: {e}")
            return False
        finally:
            self._running = False
            self._stopped_at = datetime.now()

    def stop_capture(self):
        """Stop the packet capture (takes effect within ~1 second)."""
        self._running = False

    def status(self) -> dict:
        """Capture status for the API."""
        duration = 0.0
        if self._started_at:
            end = self._stopped_at or datetime.now()
            duration = max(0.0, (end - self._started_at).total_seconds())
        return {
            "running": self._running,
            "interface": self._interface_label or self._interface,
            "packets_captured": self._packet_count,
            "bytes_captured": self._bytes_captured,
            "duration": round(duration, 1),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "error": self.last_error,
            "admin": is_admin() if sys.platform == "win32" else True,
        }

    def _handle_packet(self, pkt):
        """Process a single captured packet and convert to our Packet model."""
        if not self._running:
            return

        self._packet_count += 1
        self._bytes_captured += len(pkt)

        try:
            source = "?"
            destination = "?"
            protocol = "UNKNOWN"
            src_port = None
            dst_port = None
            tcp_flags = None
            src_mac = None
            dst_mac = None
            raw_info = ""

            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst

            if pkt.haslayer(ARP):
                source = pkt[ARP].psrc or "?"
                destination = pkt[ARP].pdst or "?"
                protocol = "ARP"
                src_mac = src_mac or pkt[ARP].hwsrc
                dst_mac = dst_mac or pkt[ARP].hwdst

            elif pkt.haslayer(IP):
                source = pkt[IP].src
                destination = pkt[IP].dst

                if pkt.haslayer(TCP):
                    protocol = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    if pkt[TCP].flags is not None:
                        tcp_flags = str(pkt[TCP].flags)
                elif pkt.haslayer(UDP):
                    protocol = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                elif pkt.haslayer(ICMP):
                    protocol = "ICMP"
                else:
                    # Keep protocol a string — Packet.get_protocol() calls .upper()
                    num = pkt[IP].proto
                    protocol = IP_PROTO_NAMES.get(num, f"IP-{num}")

            length = len(pkt)

            try:
                raw_info = str(pkt.summary())[:200]
            except Exception:
                raw_info = ""

            packet = Packet(
                timestamp=datetime.now(),
                source=source,
                destination=destination,
                protocol=protocol,
                length=length,
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags=tcp_flags,
                src_mac=src_mac,
                dst_mac=dst_mac,
                interface=self._interface_label,
                direction=ip_direction(source, destination),
                raw_info=raw_info,
            )
            self._process_packet(packet)

        except Exception as e:
            logger.warning(f"Failed to process packet: {e}")

    def _process_packet(self, packet: Packet):
        """Call the user callback with the parsed packet."""
        if self._packet_callback:
            self._packet_callback(packet)

    def get_packet_count(self) -> int:
        """Get the number of packets captured so far."""
        return self._packet_count

    def get_interface(self) -> Optional[str]:
        """Get the current capture interface."""
        return self._interface

