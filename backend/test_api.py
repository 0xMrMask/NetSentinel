"""
API smoke test using Flask's built-in test client (no live server needed).
Run: python test_api.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import main

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE, "samples", "sample_scan.csv")


def main_test():
    client = main.app.test_client()
    failures = []

    # 1. Status
    r = client.get("/api/status")
    assert r.status_code == 200 and r.get_json()["status"] == "ok", "status failed"
    print("GET  /api/status         -> 200 OK")

    # 2. Interfaces
    r = client.get("/api/interfaces")
    data = r.get_json()
    assert r.status_code == 200 and data["interfaces"], "interfaces failed"
    print(f"GET  /api/interfaces     -> 200 OK ({len(data['interfaces'])} interfaces)")

    # 3. Config
    r = client.get("/api/config")
    assert r.status_code == 200 and "time_window" in r.get_json(), "config failed"
    print("GET  /api/config         -> 200 OK")

    # 4. Start validation (no interface -> 400)
    r = client.post("/api/start", json={})
    assert r.status_code == 400, "start validation failed"
    print("POST /api/start (empty)  -> 400 OK")

    # 5. Data (empty state)
    r = client.get("/api/data")
    assert r.status_code == 200 and "packets" in r.get_json(), "data failed"
    print("GET  /api/data           -> 200 OK")

    # 5b. Analyze with no packets -> 400 with friendly error
    r = client.post("/api/analyze")
    assert r.status_code == 400 and "error" in r.get_json(), "analyze-empty failed"
    print("POST /api/analyze (empty)-> 400 OK")

    # 5c. Inject a couple of fake captured packets, then analyze
    from datetime import datetime as dt
    from models import Packet
    with main.live_lock:
        for i in range(5):
            main.live_packets.append(Packet(
                timestamp=dt.now(), source="10.0.0.2", destination="10.0.0.1",
                protocol="TCP", length=120, dst_port=443))
    r = client.post("/api/analyze")
    assert r.status_code == 200, "analyze failed"
    a = r.get_json()
    assert a["packets_loaded"] == 5 and "investigation_score" in a, "analyze payload wrong"
    print(f"POST /api/analyze        -> 200 OK ({a['packets_loaded']} packets)")

    # 5d. Clear captured data
    r = client.post("/api/clear")
    assert r.status_code == 200, "clear failed"
    data = client.get("/api/data").get_json()
    assert data["packets"]["total_packets"] == 0, "clear did not reset packets"
    print("POST /api/clear          -> 200 OK")

    # 6. CSV analyze with the sample file
    with open(CSV_PATH, "rb") as f:
        r = client.post("/api/csv/analyze", data={"file": (f, "sample_scan.csv")},
                        content_type="multipart/form-data")
    assert r.status_code == 200, f"csv analyze failed: {r.status_code} {r.get_json()}"
    analysis = r.get_json()
    assert analysis["packets_loaded"] > 0, "no packets in analysis"
    assert analysis["alerts"], "no alerts in analysis"
    score = analysis["investigation_score"]
    print(f"POST /api/csv/analyze    -> 200 OK "
          f"({analysis['packets_loaded']} packets, {len(analysis['alerts'])} alerts, "
          f"score={score['total_score']})")

    # 6b. Save the analysis as a report (JSON + HTML on disk)
    r = client.post("/api/save-report", json=analysis)
    assert r.status_code == 200, f"save-report failed: {r.get_json()}"
    saved = r.get_json()
    import os as _os
    html_path = _os.path.join(main.REPORTS_DIR, saved["html"])
    json_path = _os.path.join(main.REPORTS_DIR, saved["json"])
    assert _os.path.exists(html_path) and _os.path.exists(json_path), "report files missing"
    print(f"POST /api/save-report    -> 200 OK ({saved['html']})")

    # 6c. List saved reports
    r = client.get("/api/reports")
    assert r.status_code == 200 and r.get_json()["reports"], "reports list empty"
    print(f"GET  /api/reports        -> 200 OK ({len(r.get_json()['reports'])} listed)")

    # 6d. View the HTML report
    r = client.get("/api/reports/" + saved["html"])
    assert r.status_code == 200 and b"NetSentinel" in r.data, "report fetch failed"
    assert b"INVESTIGATION SCORE" in r.data.upper() or b"Alerts" in r.data, "report content wrong"
    print("GET  /api/reports/<name> -> 200 OK (valid HTML)")

    # 6e. Validation: empty save rejected, bad names blocked
    assert client.post("/api/save-report", json={}).status_code == 400, "empty save not rejected"
    bad = client.get("/api/reports/..%2fsecrets.txt")
    assert bad.status_code in (400, 404), "path traversal not blocked"
    missing = client.get("/api/reports/report_does_not_exist.html")
    assert missing.status_code == 404, "missing report should 404"
    print("report validation        -> OK")

    # cleanup test files (best-effort — Windows may briefly hold the file)
    import time as _time
    for f in (saved["json"], saved["html"]):
        p = _os.path.join(main.REPORTS_DIR, f)
        for _attempt in range(5):
            try:
                if _os.path.exists(p):
                    _os.remove(p)
                break
            except PermissionError:
                _time.sleep(0.3)

    # 7. Index page
    r = client.get("/")
    assert r.status_code == 200, "index failed"
    assert b"NetSentinel" in r.data, "index content wrong"
    print("GET  /                   -> 200 OK")

    # 8. Static assets
    for path in ("/styles.css", "/script.js"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} failed"
        print(f"GET  {path:<20} -> 200 OK")

    print("\nAPI SMOKE TEST PASSED")


if __name__ == "__main__":
    main_test()
