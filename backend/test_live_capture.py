"""
Live capture test for Windows 11: validates interface resolution,
non-admin capture, packet parsing (timestamp/protocol), and stop latency.
Run: python test_live_capture.py
"""
import socket
import sys
import threading
import time
from datetime import datetime

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capture import PacketCaptureEngine, npcap_installed, resolve_interface


def make_traffic():
    """Generate a few IP packets (DNS queries) so the sniffer has something."""
    for host in ("example.com", "google.com", "cloudflare.com"):
        try:
            socket.getaddrinfo(host, 80)
        except Exception:
            pass


def main():
    print(f"Npcap installed: {npcap_installed()}")
    assert npcap_installed(), "Npcap missing - install from https://npcap.com"

    # 1. Friendly name resolution
    resolved = resolve_interface("Wi-Fi")
    print(f"resolve_interface('Wi-Fi') -> {resolved}")
    assert resolved != "", "resolution failed"

    # 2. Validation
    engine = PacketCaptureEngine()
    err = engine.validate("")
    assert err, "validate('') should return an error"
    print(f"validate('') -> error as expected: {err}")

    # Pick the default-route interface (the one actually carrying traffic)
    from scapy.all import conf
    default_iface = conf.route.route("8.8.8.8")[0]
    print(f"Default route interface: {default_iface}")

    err = engine.validate(str(default_iface))
    print(f"validate(default iface) -> {err}")
    assert err is None, f"validation failed: {err}"

    # 3. Real capture for 3 seconds with generated traffic
    packets = []
    engine.set_callback(packets.append)
    t = threading.Thread(target=engine.start_capture, args=(str(default_iface),), daemon=True)
    t.start()
    time.sleep(0.5)
    make_traffic()
    time.sleep(2.5)

    status = engine.status()
    print(f"status while running: {status}")
    assert status["running"], "engine should be running"
    print(f"packets received: {len(packets)}")
    assert len(packets) > 0, "no packets captured - interface may be idle/blocked"

    # 4. Verify packet fields (the old code had timestamp=None -> crash)
    for p in packets[:10]:
        assert isinstance(p.timestamp, datetime), "packet timestamp must be datetime"
        assert isinstance(p.get_protocol(), str), "protocol must be a string"

    # 5. Stop latency must be <= ~2s even with no further traffic
    t0 = time.monotonic()
    engine.stop_capture()
    t.join(timeout=4)
    elapsed = time.monotonic() - t0
    print(f"stop latency: {elapsed:.2f}s (joined={not t.is_alive()})")
    assert not t.is_alive(), "stop_capture did not stop the capture loop"
    assert elapsed < 3, f"stop too slow: {elapsed:.2f}s"
    assert engine.status()["running"] is False

    print("\nLIVE CAPTURE TEST PASSED (Windows 11)")


if __name__ == "__main__":
    main()
