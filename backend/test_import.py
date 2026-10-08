"""Import test for the full NetSentinel backend."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("1. models...", end=" ")
from models import Packet, TrafficStats, InvestigationScore, Alert, DetectionRule
print("OK")

print("2. parser...", end=" ")
from parser import parse_csv
print("OK")

print("3. detector...", end=" ")
from detector import DetectionEngine, DEFAULT_THRESHOLDS
e = DetectionEngine()
rules = [n for n in dir(e) if n.startswith("rule_")]
assert len(rules) == 9, f"Expected 9 rules, got {len(rules)}"
print(f"OK ({len(rules)} rules)")

print("4. capture...", end=" ")
from capture import PacketCaptureEngine
print("OK")

print("5. main (Flask)...", end=" ")
import main
print("OK")

# Verify Flask routes registered
routes = sorted(str(r) for r in main.app.url_map.iter_rules())
print("\nRegistered routes:")
for r in routes:
    print("  ", r)

print("\nALL IMPORTS PASSED")

