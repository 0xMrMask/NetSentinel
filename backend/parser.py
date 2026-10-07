"""CSV parser for Wireshark-style exports and NetSentinel sample CSVs."""
import csv
from datetime import datetime
from models import Packet

ALIASES={"time":["time","frame.time","timestamp"],"src":["src","ip.src","source"],"dst":["dst","ip.dst","destination"],"proto":["proto","_ws.col.protocol","protocol"],"length":["length","frame.len","len"]}

def _field(row,key):
    lower={str(k).strip().lower():v for k,v in row.items()}
    for name in ALIASES[key]:
        if name.lower() in lower: return lower[name.lower()]
    return ""

def parse_csv(path):
    packets=[]; warnings=[]; missing=[]
    try:
        with open(path,"r",encoding="utf-8-sig",newline="") as f: rows=list(csv.DictReader(f))
    except Exception as e: return {"packets":[],"parsing_status":"ERROR","warnings":[str(e)],"missing_fields":[]}
    if not rows: return {"packets":[],"parsing_status":"ERROR","warnings":["CSV contains no data rows."],"missing_fields":[]}
    for key in ("src","dst","proto","length"):
        if not any(_field(r,key) for r in rows): missing.append(key)
    if missing: return {"packets":[],"parsing_status":"ERROR","warnings":[],"missing_fields":missing}
    for i,row in enumerate(rows,1):
        try:
            ts=datetime.now()
            raw=_field(row,"time")
            if raw:
                try: ts=datetime.fromisoformat(raw.replace("Z","+00:00"))
                except Exception: pass
            length=int(float(_field(row,"length") or 0))
            packets.append(Packet(ts,_field(row,"src") or "-",_field(row,"dst") or "-",(_field(row,"proto") or "UNKNOWN").upper(),length))
        except Exception as e: warnings.append(f"Row {i}: {e}")
    status="WARNING" if warnings else "OK"
    return {"packets":packets,"parsing_status":status,"warnings":warnings,"missing_fields":missing}
