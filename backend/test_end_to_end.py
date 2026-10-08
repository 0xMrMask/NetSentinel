"""
End-to-end test: sample CSV -> parser -> detection engine -> investigation score.
Run: python test_end_to_end.py
"""
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser import parse_csv
from detector import DetectionEngine

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE, "samples", "sample_scan.csv")

def main():
    if not os.path.exists(CSV_PATH):
        print("Sample CSV not found. Run generate_sample.py first.")
        sys.exit(1)

    print("Parsing:", CSV_PATH)
    result = parse_csv(CSV_PATH)

    status = result["parsing_status"]
    packets = result["packets"]
    print(f"  status={status}  packets={len(packets)}  missing={result['missing_fields']}")

    if status == "ERROR" or not packets:
        print("FAIL: no packets parsed")
        print("warnings:", result["warnings"])
        sys.exit(1)

    engine = DetectionEngine()
    now = datetime.now()
    alerts = engine.detect(packets, now)
    score = engine.compute_investigation_score(packets, now)

    print(f"\nAlerts fired: {len(alerts)}")
    for a in alerts:
        print(f"  [{a.severity}] {a.rule_name}  source={a.source}")
        print(f"    {a.evidence}")

    print(f"\nInvestigation score: {score.total_score}")
    for c in score.contributions:
        print(f"  +{c['score']}  {c['label']}: {c['reason']}")

    fired = {a.rule_name for a in alerts}
    expected = {"PORT SCAN DETECTED", "POSSIBLE NETWORK SCANNING", "HIGH ICMP TRAFFIC",
                "REPEATED COMMUNICATION", "HIGH PACKET VOLUME"}
    matched = fired & expected
    print(f"\nExpected-rule matches: {sorted(matched)}")

    if not alerts:
        print("FAIL: no alerts fired")
        sys.exit(1)

    print("\nEND-TO-END TEST PASSED")

if __name__ == "__main__":
    main()
