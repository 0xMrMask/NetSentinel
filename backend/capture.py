"""Scapy/Npcap packet capture adapter for local Windows/Linux use."""
from datetime import datetime
import threading

class PacketCaptureEngine:
    def __init__(self):
        self.sniffer=None; self.callback=None; self.interface=None; self.error=None; self._lock=threading.Lock(); self.packets_captured=0

    def set_callback(self, callback): self.callback=callback

    def validate(self, interface):
        try:
            from scapy.all import get_if_list, sniff
            if interface not in get_if_list():
                # Scapy's Windows table may accept a friendly key even when raw list differs.
                from scapy.all import conf
                if interface not in conf.ifaces: return f"Interface not found: {interface}"
            sniff(iface=interface, count=0, timeout=0.1, store=False)
            return None
        except Exception as e:
            return f"Packet capture validation failed: {e}"

    def start_capture(self, interface, packet_filter="ip"):
        try:
            from scapy.all import AsyncSniffer
            self.interface=interface; self.error=None; self.packets_captured=0
            self.sniffer=AsyncSniffer(iface=interface, filter=packet_filter, prn=self._handle_packet, store=False)
            self.sniffer.start()
        except Exception as e:
            self.error=str(e)

    def _handle_packet(self, raw):
        try:
            from scapy.all import IP, TCP, UDP, ICMP, DNS, ARP
            if raw.haslayer(ARP):
                src=raw[ARP].psrc; dst=raw[ARP].pdst; proto="ARP"; sp=dp=None
            elif raw.haslayer(IP):
                ip=raw[IP]; src=ip.src; dst=ip.dst; sp=dp=None
                if raw.haslayer(TCP): proto="TCP"; sp=raw[TCP].sport; dp=raw[TCP].dport
                elif raw.haslayer(UDP): proto="DNS" if raw.haslayer(DNS) else "UDP"; sp=raw[UDP].sport; dp=raw[UDP].dport
                elif raw.haslayer(ICMP): proto="ICMP"
                else: proto="IP"
            else: return
            from models import Packet
            p=Packet(datetime.now(),src,dst,proto,len(raw),sp,dp)
            if raw.haslayer(TCP): p.tcp_flags=str(raw[TCP].flags)
            self.packets_captured += 1
            if self.callback: self.callback(p)
        except Exception as e: self.error=str(e)

    def stop_capture(self):
        try:
            if self.sniffer and getattr(self.sniffer,"running",False): self.sniffer.stop()
        except Exception as e: self.error=str(e)

    def status(self):
        return {"running": bool(self.sniffer and getattr(self.sniffer,"running",False)),"interface":self.interface,"packets_captured":self.packets_captured,"error":self.error}
