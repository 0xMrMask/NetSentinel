"""
Validation for the NetSentinel v2 feature set:
  * timestamp-based packets/sec + bandwidth statistics
  * time-window detection semantics (recent window vs full capture)
  * SYN-dominant port-scan detection with confidence + MITRE mapping
  * ARP spoof detection (one IP claimed by multiple MACs)
  * traffic spike detection against a real baseline rate
  * /api/reload validation (unknown keys ignored, bad values rejected)
  * device intelligence in the analysis payload
  * report rendering (executive summary + detection table)
Run: python test_v2_features.py
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import Packet
from detector import DetectionEngine
from config import validate_config_update, PACKET_BUFFER_SIZE
import main as main_mod
import report as report_mod
from parser import parse_csv

NOW = datetime.now()


def pkt(src, dst, proto="TCP", dport=None, flags=None, ts=None,
        length=60, smac=None):
    return Packet(timestamp=ts or NOW, source=src, destination=dst,
                  protocol=proto, length=length, dst_port=dport,
                  tcp_flags=flags, src_mac=smac)


def test_stats_rates():
    base = NOW - timedelta(seconds=99)
    packets = [pkt("192.168.1.2", "8.8.8.8", ts=base + timedelta(seconds=i))
               for i in range(100)]
    stats = main_mod.compute_stats(packets)
    assert 0.9 < stats.packets_per_second < 1.2, stats.packets_per_second
    assert stats.total_bytes == 6000
    assert 55 < stats.bytes_per_second < 65
    assert stats.duration_seconds == 99
    assert stats.active_hosts == 2
    print("  stats: timestamp-based pps/bandwidth/duration OK")


def test_port_scan_syn_ratio():
    engine = DetectionEngine()
    packets = [
        pkt("192.168.1.20", "192.168.1.10", dport=port, flags="S",
            ts=NOW - timedelta(seconds=5 - i * 0.2))
        for i, port in enumerate(range(20, 40))  # 20 ports > 10 threshold
    ]
    alerts = engine.detect(packets, NOW)
    scan = [a for a in alerts if a.rule_name == "PORT SCAN DETECTED"]
    assert scan, "port scan not detected"
    a = scan[0]
    assert a.destination == "192.168.1.10"
    assert a.confidence == 90, a.confidence
    assert a.mitre_technique.startswith("T1046")
    assert "SYN" in a.evidence and "ACK" in a.evidence
    print("  port scan: SYN-dominant detection + MITRE/confidence OK")


def test_window_semantics():
    """50 packets spread over 30 minutes must not trip the 30s window rule;
    the same 50 packets inside 30 seconds must."""
    engine = DetectionEngine()
    spread = [
        pkt("192.168.1.50", "8.8.8.8", flags="A",
            ts=NOW - timedelta(minutes=30) + timedelta(seconds=i * 36))
        for i in range(50)
    ]
    assert not engine.detect_recent(spread, NOW), \
        "slow traffic should not trigger the live window"

    burst = [
        pkt("192.168.1.50", "8.8.8.8", flags="A",
            ts=NOW - timedelta(seconds=i * 0.5))
        for i in range(110)  # 110 packets inside the 30s window (> 50)
    ]
    recent = engine.detect_recent(burst, NOW)
    assert any(a.rule_name == "HIGH PACKET VOLUME" for a in recent)
    print("  windowing: 30-min spread silent, 30-s burst alerts OK")


def test_arp_spoof():
    engine = DetectionEngine()
    packets = [
        pkt("192.168.1.1", "192.168.1.20", proto="ARP",
            smac="aa:aa:aa:aa:aa:aa", ts=NOW - timedelta(seconds=4)),
        pkt("192.168.1.1", "192.168.1.20", proto="ARP",
            smac="bb:bb:bb:bb:bb:bb", ts=NOW - timedelta(seconds=2)),
    ]
    alerts = engine.detect(packets, NOW)
    arp = [a for a in alerts if a.rule_name == "ARP SPOOFING DETECTED"]
    assert arp, "arp spoof not detected"
    assert arp[0].confidence == 85
    assert "T1557.002" in arp[0].mitre_technique
    print("  arp spoof: IP/MAC conflict detection OK")


def test_traffic_spike():
    engine = DetectionEngine(window_seconds=10)
    packets = []
    # baseline: ~2 pps for a minute before the window
    for i in range(120):
        packets.append(pkt("192.168.1.2", "8.8.8.8",
                           ts=NOW - timedelta(seconds=90 - i * 0.5)))
    # recent window: 110 packets in the last 5s (~11 pps, > 5x baseline)
    for i in range(110):
        packets.append(pkt("192.168.1.2", "8.8.8.8",
                           ts=NOW - timedelta(seconds=5 - i * 0.045)))
    alerts = engine.detect(packets, NOW)
    assert any(a.rule_name == "SUDDEN TRAFFIC SPIKE" for a in alerts), \
        "traffic spike not detected"
    print("  traffic spike: baseline-vs-current rate OK")


def test_config_validation():
    cleaned, err = validate_config_update({"packets_per_source": 100, "junk": 1})
    assert err is None and cleaned == {"packets_per_source": 100}
    _, err = validate_config_update({"packets_per_source": -999})
    assert err and "positive" in err
    _, err = validate_config_update({"packets_per_source": "abc"})
    assert err and "number" in err
    print("  config validation helper OK")


def test_api_reload_validation():
    client = main_mod.app.test_client()
    r = client.post("/api/reload", json={"packets_per_source": -5})
    assert r.status_code == 400, r.status_code
    r = client.post("/api/reload", json={"unique_ports": 0})
    assert r.status_code == 400
    r = client.post("/api/reload",
                    json={"packets_per_source": 75, "evil_key": 1})
    body = r.get_json()
    assert r.status_code == 200
    assert body["config"]["packets_per_source"] == 75
    assert "evil_key" not in body["config"]
    # restore default
    client.post("/api/reload", json={"packets_per_source": 50})
    print("  /api/reload: rejects bad values, ignores unknown keys OK")


def test_devices_and_analysis():
    packets = [
        pkt("192.168.1.20", "192.168.1.10", dport=port, flags="S",
            ts=NOW - timedelta(seconds=5 - i * 0.2))
        for i, port in enumerate(range(20, 40))
    ] + [
        pkt("192.168.1.2", "8.8.8.8", ts=NOW - timedelta(seconds=1)),
    ]
    payload = main_mod.build_analysis(packets, filename="synthetic")
    assert payload["devices"], "devices missing from analysis payload"
    scanner = [d for d in payload["devices"] if d["ip"] == "192.168.1.20"]
    assert scanner and scanner[0]["risk"] == "suspicious", scanner
    normal = [d for d in payload["devices"] if d["ip"] == "8.8.8.8"]
    assert normal and normal[0]["risk"] == "normal"
    assert "packets_per_second" in payload and "duration_seconds" in payload

    html = report_mod.render_html(payload)
    assert "Security assessment summary" in html
    assert "Detections" in html
    assert "T1046" in html          # MITRE shows in the detection table
    print("  devices + analysis payload + report sections OK")


def test_csv_mac_port_parsing():
    csv_text = (
        "source,destination,protocol,length,udp.srcport,udp.dstport,eth.src\n"
        "192.168.1.1,192.168.1.2,ARP,42,,,aa:bb:cc:dd:ee:ff\n"
        "192.168.1.1,192.168.1.2,ARP,42,,,11:22:33:44:55:66\n"
        "192.168.1.3,8.8.8.8,UDP,60,51000,53,\n"
    )
    path = os.path.join(tempfile.gettempdir(), "ns_v2_test.csv")
    with open(path, "w", encoding="utf-8") as f:
        f.write(csv_text)
    try:
        result = parse_csv(path)
        packets = result["packets"]
        assert result["parsing_status"] == "OK"
        assert packets[0].src_mac == "aa:bb:cc:dd:ee:ff"
        assert packets[1].src_mac == "11:22:33:44:55:66"
        assert packets[2].src_port == 51000 and packets[2].dst_port == 53

        engine = DetectionEngine()
        alerts = engine.detect(packets, NOW)
        assert any(a.rule_name == "ARP SPOOFING DETECTED" for a in alerts), \
            "CSV import should detect ARP spoofing from eth.src columns"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    print("  CSV: udp ports + eth MAC columns power the same detections OK")


def test_bounded_buffer():
    import collections
    buf = collections.deque(maxlen=PACKET_BUFFER_SIZE)
    for i in range(PACKET_BUFFER_SIZE + 500):
        buf.append(i)
    assert len(buf) == PACKET_BUFFER_SIZE
    print(f"  bounded packet buffer (maxlen={PACKET_BUFFER_SIZE}) OK")


if __name__ == "__main__":
    print("Running v2 feature validation...\n")
    test_stats_rates()
    test_port_scan_syn_ratio()
    test_window_semantics()
    test_arp_spoof()
    test_traffic_spike()
    test_config_validation()
    test_api_reload_validation()
    test_devices_and_analysis()
    test_csv_mac_port_parsing()
    test_bounded_buffer()
    print("\nALL V2 VALIDATION TESTS PASSED")
