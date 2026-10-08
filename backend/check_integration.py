"""Integration checker: verifies frontend files are consistent with each
other and that every API endpoint they call exists in the backend."""
import re
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FE = os.path.join(BASE, "web")

html = open(os.path.join(FE, "index.html"), encoding="utf-8").read()
js = open(os.path.join(FE, "script.js"), encoding="utf-8").read()
css = open(os.path.join(FE, "styles.css"), encoding="utf-8").read()

# 1. Every getElementById(...) in JS must exist in the HTML
ids_used = set(re.findall(r'getElementById\("([^"]+)"\)', js))
ids_defined = set(re.findall(r'id="([^"]+)"', html))
missing_ids = sorted(ids_used - ids_defined)
print(f"IDs used in JS: {len(ids_used)}")
print("  missing in HTML:", missing_ids if missing_ids else "NONE")

# 2. Every onclick/onchange handler in HTML must exist in JS
handlers = set(re.findall(r'on(?:click|change)="([A-Za-z0-9_]+)\(', html))
funcs = set(re.findall(r'(?:async )?function ([A-Za-z0-9_]+)', js))
missing_f = sorted(handlers - funcs)
print("HTML event handlers:", sorted(handlers))
print("  missing in JS:", missing_f if missing_f else "NONE")

# 3. CSS variables used by JS must be defined in CSS
vars_js = set(re.findall(r'var\(--([a-z0-9-]+)\)', js))
vars_css = set(re.findall(r'--([a-z0-9-]+):', css))
missing_v = sorted(vars_js - vars_css)
print("CSS vars used in JS:", sorted(vars_js))
print("  missing in CSS:", missing_v if missing_v else "NONE")

# 4. API endpoints used by JS must exist in backend routes
endpoints = set(re.findall(r'fetchJSON?\("(/api/[a-z/]+)"', js))
endpoints |= set(re.findall(r'fetch\("(/api/[a-z/]+)"', js))
sys.path.insert(0, os.path.join(BASE, "backend"))
import main
routes = {str(r) for r in main.app.url_map.iter_rules()}
missing_ep = sorted(e for e in endpoints if e not in routes)
print("API endpoints used:", sorted(endpoints))
print("  missing in backend:", missing_ep if missing_ep else "NONE")

# 5. Bracket balance
for name, s in [("index.html", html), ("script.js", js), ("styles.css", css)]:
    ok = s.count("{") == s.count("}") and s.count("(") == s.count(")")
    print(f"{name}: {'BALANCED' if ok else 'MISMATCH'}")

# 6. Flask asset routes referenced by HTML
for asset in re.findall(r'(?:href|src)="(/[^"]+)"', html):
    if asset.startswith("/api"):
        continue
    ok = asset in routes or asset in ("/styles.css", "/script.js")
    print(f"asset {asset}: {'OK' if ok else 'NOT SERVED'}")

fails = missing_ids or missing_f or missing_v or missing_ep
print("\nINTEGRATION CHECK:", "FAILED" if fails else "PASSED")
