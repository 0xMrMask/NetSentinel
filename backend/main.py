"""
NetSentinel — Main Server
Flask web server with a local API. Live updates use 1-second polling
from the dashboard (no external services).
Everything listens only on 127.0.0.1 (localhost).
"""

from datetime import datetime
from typing import List
from flask import Flask, request, jsonify, Response, send_from_directory
from models import Packet, TrafficStats, InvestigationScore, Alert
from detector import DetectionEngine
from capture import PacketCaptureEngine
from parser import parse_csv
from config import DETECTION_CONFIG, PACKET_BUFFER_SIZE, validate_config_update
from collections import deque
import os
import threading
import time
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "web"))

app = Flask(__name__,
            static_folder=FRONTEND_DIR,
            static_url_path="")

# ============================================================
# GLOBAL STATE
# ============================================================

capture_engine = PacketCaptureEngine()
detector = DetectionEngine()

# Live monitoring state — bounded buffer so memory cannot grow forever
live_packets = deque(maxlen=PACKET_BUFFER_SIZE)
live_lock = threading.Lock()
live_stats = TrafficStats()
live_alerts: List[Alert] = []

# Thresholds (configurable at runtime via /api/reload — validated in config.py)
config = dict(DETECTION_CONFIG)

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def compute_stats(packets: List[Packet]) -> TrafficStats:
    """Compute traffic statistics from a list of packets."""
    stats = TrafficStats()
    stats.total_packets = len(packets)

    if not packets:
        return stats

    src_counts = {}
    dst_counts = {}
    proto_counts = {}
    src_ports = {}
    total_length = 0

    for p in packets:
        src = p.get_src_ip()
        dst = p.get_dst_ip()
        proto = p.get_protocol()

        src_counts[src] = src_counts.get(src, 0) + 1
        dst_counts[dst] = dst_counts.get(dst, 0) + 1
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
        total_length += p.length

        if p.src_port:
            src_ports[str(p.src_port)] = src_ports.get(str(p.src_port), 0) + 1

    stats.source_counts = src_counts
    stats.destination_counts = dst_counts
    stats.protocol_counts = proto_counts
    stats.source_ports = src_ports

    stats.unique_sources = len(src_counts)
    stats.unique_destinations = len(dst_counts)

    if src_counts:
        stats.most_active_source = max(src_counts, key=src_counts.get)
    if dst_counts:
        stats.most_contacted_destination = max(dst_counts, key=dst_counts.get)
    if proto_counts:
        stats.most_common_protocol = max(proto_counts, key=proto_counts.get)

    stats.tcp_count = proto_counts.get("TCP", 0)
    stats.udp_count = proto_counts.get("UDP", 0)
    stats.dns_count = proto_counts.get("DNS", 0)
    stats.icmp_count = proto_counts.get("ICMP", 0)
    stats.arp_count = proto_counts.get("ARP", 0)

    stats.avg_packet_length = total_length / len(packets)

    # Active hosts: unique IPs across both directions (not the sum of both,
    # which double-counts devices that both send and receive)
    all_hosts = set(src_counts) | set(dst_counts)
    all_hosts.discard("?")
    stats.active_hosts = len(all_hosts)

    # Rates come from actual packet timestamps, not from packet counts
    stats.total_bytes = total_length
    first_ts = packets[0].timestamp
    last_ts = packets[-1].timestamp
    duration = (last_ts - first_ts).total_seconds()
    stats.duration_seconds = max(0.0, duration)
    if duration > 0:
        stats.packets_per_second = len(packets) / duration
        stats.bytes_per_second = total_length / duration

    return stats


def build_devices(packets: List[Packet], alerts: List[Alert]) -> List[dict]:
    """
    Simple device intelligence: per-IP traffic totals with a risk badge
    derived from the alerts that name that IP as the source.
    """
    suspicious = {a.source for a in alerts if a.severity == "High"}
    watch = {a.source for a in alerts if a.severity == "Medium"}

    devices = {}
    for p in packets:
        src = p.get_src_ip()
        dst = p.get_dst_ip()
        for ip in (src, dst):
            if not ip or ip == "?":
                continue
            entry = devices.setdefault(ip, {"ip": ip, "packets": 0, "bytes": 0})
            entry["packets"] += 1
        if src and src != "?":
            devices[src]["bytes"] += p.length

    out = []
    for ip, entry in devices.items():
        if ip in suspicious:
            risk = "suspicious"
        elif ip in watch:
            risk = "watch"
        else:
            risk = "normal"
        out.append({**entry, "risk": risk})
    out.sort(key=lambda d: d["bytes"], reverse=True)
    return out[:20]


def run_detection(packets: List[Packet], now: datetime, recent_only=False) -> List[Alert]:
    """Run detection rules on packets.
    recent_only=True evaluates just the current time window (live dashboard);
    otherwise the whole capture is scanned window-by-window (analysis/reports)."""
    engine = DetectionEngine(thresholds=config, window_seconds=config["time_window"])
    if recent_only:
        return engine.detect_recent(packets, now)
    return engine.detect(packets, now)


_last_recompute = 0.0


def process_packet(packet: Packet, update_stats: bool = True):
    """Store the packet; recompute stats+detection at most twice per second
    so a busy interface cannot make the server lag (O(n) per recompute)."""
    global live_packets, live_stats, live_alerts, _last_recompute

    with live_lock:
        live_packets.append(packet)
        if not update_stats:
            return
        now_mono = time.monotonic()
        if now_mono - _last_recompute < 0.5 and len(live_packets) < 5000:
            return
        _last_recompute = now_mono
        live_stats = compute_stats(live_packets)
        # Live alerts reflect the current detection window only
        live_alerts = run_detection(live_packets, datetime.now(), recent_only=True)


# ============================================================
# API ENDPOINTS
# ============================================================

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/styles.css")
def serve_styles():
    return send_from_directory(FRONTEND_DIR, "styles.css")


@app.route("/script.js")
def serve_script():
    return send_from_directory(FRONTEND_DIR, "script.js")


@app.route("/api/status")
def api_status():
    return jsonify({
        "status": "ok",
        "service": "NetSentinel",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    interfaces = get_available_interfaces()
    return jsonify({"interfaces": interfaces})


@app.route("/api/start", methods=["POST"])
def api_start():
    """Start live packet capture."""
    global live_packets, live_stats, live_alerts

    data = request.get_json(silent=True) or {}
    interface = data.get("interface", "")
    time_window = data.get("time_window", 30)

    if not interface:
        return jsonify({"error": "No interface specified"}), 400

    # Synchronous pre-flight: Npcap present, interface exists, dry-run sniff
    error = capture_engine.validate(interface)
    if error:
        return jsonify({"error": error}), 500

    # Reset state
    live_packets = deque(maxlen=PACKET_BUFFER_SIZE)
    live_stats = TrafficStats()
    live_alerts = []

    # Start capture in a background thread
    def capture_loop():
        capture_engine.set_callback(lambda pkt: process_packet(pkt, update_stats=True))
        capture_engine.start_capture(interface, packet_filter="ip or arp")

    thread = threading.Thread(target=capture_loop, daemon=True)
    thread.start()

    return jsonify({
        "status": "started",
        "interface": interface,
        "time_window": time_window,
    })


@app.route("/api/stop", methods=["POST"])
def api_stop():
    """Stop the live capture."""
    capture_engine.stop_capture()
    return jsonify({"status": "stopped"})


@app.route("/api/data", methods=["GET"])
def api_data():
    """Get current live monitoring data."""
    global live_packets, live_stats, live_alerts

    with live_lock:
        packets = list(live_packets)
        stats = live_stats
        alerts = list(live_alerts)

    return jsonify({
        "packets": stats.to_dict(),
        "capture": capture_engine.status(),
        "packets_list": [{
            "time": p.timestamp.strftime("%H:%M:%S") if p.timestamp else "",
            "src": p.get_src_ip(),
            "dst": p.get_dst_ip(),
            "proto": p.get_protocol(),
            "length": p.length,
        } for p in packets[-100:]],
        "alerts": [a.to_dict() for a in alerts],
    })


def build_analysis(packets, filename, parsing_status="OK",
                   warnings=None, missing_fields=None):
    """Build the full analysis payload for a list of packets.
    Used by both live-capture analysis and CSV analysis."""
    stats = compute_stats(packets)
    now = datetime.now()
    # Full analysis: window-by-window detection across the whole capture
    alerts = run_detection(packets, now)

    engine = DetectionEngine(thresholds=config, window_seconds=config["time_window"])
    score = engine.compute_investigation_score(packets, now)

    top_sources = sorted(stats.source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_sources = [{"ip": ip, "count": count} for ip, count in top_sources]

    top_destinations = sorted(stats.destination_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_destinations = [{"ip": ip, "count": count} for ip, count in top_destinations]

    return {
        "filename": filename,
        "packets_loaded": len(packets),
        "parsing_status": parsing_status,
        "missing_fields": missing_fields or [],
        "warnings": warnings or [],
        "unique_sources": stats.unique_sources,
        "unique_destinations": stats.unique_destinations,
        "active_hosts": stats.active_hosts,
        "packets_per_second": round(stats.packets_per_second, 1),
        "bytes_per_second": round(stats.bytes_per_second, 2),
        "total_bytes": stats.total_bytes,
        "duration_seconds": round(stats.duration_seconds, 1),
        "protocol_distribution": stats.protocol_counts,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "avg_packet_length": stats.avg_packet_length,
        "most_active_source": stats.most_active_source,
        "most_contacted_destination": stats.most_contacted_destination,
        "devices": build_devices(packets, alerts),
        "alerts": [a.to_dict() for a in alerts],
        "investigation_score": score.to_dict(),
    }


@app.route("/api/analyze", methods=["POST"])
def api_analyze_captured():
    """Run full analysis on the packets captured in this session."""
    global live_packets
    with live_lock:
        packets = list(live_packets)

    if not packets:
        return jsonify({"error": "No captured packets yet. Start a capture first "
                                 "(or upload a CSV instead)."}), 400

    analysis = build_analysis(packets, filename="Live capture")
    return jsonify(analysis)


@app.route("/api/clear", methods=["POST"])
def api_clear_capture():
    """Clear captured packets, stats and alerts."""
    global live_packets, live_stats, live_alerts, _last_recompute
    with live_lock:
        live_packets = deque(maxlen=PACKET_BUFFER_SIZE)
        live_stats = TrafficStats()
        live_alerts = []
        _last_recompute = 0.0
    return jsonify({"status": "cleared"})


@app.route("/api/csv/analyze", methods=["POST"])
def api_csv_analyze():
    """Analyze a Wireshark CSV file."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No filename"}), 400

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    try:
        result = parse_csv(tmp_path)

        if result["parsing_status"] == "ERROR":
            return jsonify({
                "error": "Parse error",
                "parsing_status": result["parsing_status"],
                "missing_fields": result["missing_fields"],
                "warnings": result["warnings"],
            }), 400

        packets = result["packets"]
        analysis = build_analysis(
            packets,
            filename=file.filename,
            parsing_status=result["parsing_status"],
            warnings=result["warnings"],
            missing_fields=result["missing_fields"],
        )
        return jsonify(analysis)

    finally:
        import os
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


@app.route("/api/reload", methods=["POST"])
def api_reload_config():
    """Reload configuration thresholds (validated — only known keys with
    numeric values >= 1 are accepted)."""
    global config
    data = request.get_json(silent=True) or {}
    cleaned, error = validate_config_update(data)
    if error:
        return jsonify({"error": error}), 400
    config.update(cleaned)
    return jsonify({
        "status": "config reloaded",
        "config": config,
        "updated": sorted(cleaned.keys()),
    })


@app.route("/api/config", methods=["GET"])
def api_get_config():
    """Get current configuration."""
    return jsonify(config)


# ============================================================
# REPORTS — save analysis results to reports/
# ============================================================

REPORTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
)


@app.route("/api/save-report", methods=["POST"])
def api_save_report():
    """Persist the given analysis payload as JSON + standalone HTML."""
    data = request.get_json(silent=True)
    if not data or not data.get("packets_loaded"):
        return jsonify({"error": "No analysis to save. Run an analysis first."}), 400

    os.makedirs(REPORTS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    base_name = f"report_{stamp}"
    if len([f for f in os.listdir(REPORTS_DIR) if f.startswith(base_name)]) >= 2:
        base_name += "_" + datetime.now().strftime("%f")[:-3]  # same-second saves

    with open(os.path.join(REPORTS_DIR, base_name + ".json"), "w",
              encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    from report import render_html
    with open(os.path.join(REPORTS_DIR, base_name + ".html"), "w",
              encoding="utf-8") as f:
        f.write(render_html(data))

    return jsonify({
        "status": "saved",
        "json": base_name + ".json",
        "html": base_name + ".html",
        "dir": REPORTS_DIR,
    })


@app.route("/api/reports", methods=["GET"])
def api_list_reports():
    """List saved reports (newest first)."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    reports = []
    for name in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if not name.endswith(".json"):
            continue
        try:
            st = os.stat(os.path.join(REPORTS_DIR, name))
        except OSError:
            continue
        reports.append({
            "json": name,
            "html": name[:-5] + ".html",
            "saved_at": datetime.fromtimestamp(st.st_mtime)
                            .isoformat(timespec="seconds"),
            "size": st.st_size,
        })
    return jsonify({"reports": reports[:20], "dir": REPORTS_DIR})


@app.route("/api/reports/<name>", methods=["GET"])
def api_get_report(name):
    """Serve one saved report file (HTML or JSON) for viewing/download."""
    safe = os.path.basename(name)  # strip any path traversal
    if not safe.startswith("report_") or not safe.endswith((".html", ".json")):
        return jsonify({"error": "Invalid report name"}), 400
    if not os.path.exists(os.path.join(REPORTS_DIR, safe)):
        return jsonify({"error": "Report not found"}), 404
    return send_from_directory(REPORTS_DIR, safe)


# ============================================================
# INTERFACE DISCOVERY
# ============================================================

def get_available_interfaces():
    """Get available network interfaces as a list of
    {id, name, description} dicts.
    On Windows, 'id' is the Npcap device name accepted by sniff() and
    'name' is the friendly name (e.g. 'Wi-Fi') shown in the UI."""
    interfaces = []

    # Preferred: Scapy's interface table (friendly names on Windows)
    try:
        from scapy.all import conf
        for key, iface in conf.ifaces.items():
            desc = getattr(iface, "description", "") or ""
            if "WAN Miniport" in desc:
                continue  # virtual monitor adapters, useless for capture
            friendly = getattr(iface, "name", None) or str(key)
            interfaces.append({
                "id": str(key),
                "name": friendly,
                "description": desc,
            })
    except Exception:
        pass

    # Fallback: raw device list
    if not interfaces:
        try:
            from scapy.all import get_if_list
            for dev in get_if_list():
                if dev != "lo":
                    interfaces.append({"id": dev, "name": dev, "description": ""})
        except Exception:
            pass

    # Last resort: well-known Windows names
    if not interfaces:
        for name in ["Wi-Fi", "Wi-Fi 2", "Ethernet", "Ethernet 2",
                     "Local Area Connection", "Local Area Connection 2"]:
            interfaces.append({"id": name, "name": name, "description": ""})

    # Put adapters that actually carry traffic first (Wi-Fi/Ethernet),
    # push virtual ones (Hyper-V/VMware/Bluetooth/loopback) to the bottom
    def _rank(item):
        n = (item["name"] or "").lower()
        d = (item["description"] or "").lower()
        if n in ("wi-fi", "ethernet") or n.startswith("wi-fi"):
            return 0
        if any(v in n + " " + d for v in
               ("hyper-v", "vmware", "vethernet", "bluetooth", "loopback", "virtual")):
            return 2
        return 1

    interfaces.sort(key=_rank)
    return interfaces


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("NetSentinel - Network Monitoring Dashboard")
    print("=" * 50)
    print()
    print("Starting local server on 127.0.0.1:8000")
    print("The server is bound to localhost only. It is NOT accessible from the internet.")
    print()
    print("Open your browser and navigate to: http://127.0.0.1:8000")
    print()
    print("Press Ctrl+C to stop.")
    print("=" * 50)
    print()

    app.run(
        host="127.0.0.1",
        port=8000,
        debug=False,
        threaded=True,
    )



