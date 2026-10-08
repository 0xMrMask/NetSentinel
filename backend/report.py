"""
NetSentinel — Report Renderer
Builds a standalone, printable HTML report from an analysis payload.
Everything is local; no external assets, scripts or fonts.
"""

import html as _html
from datetime import datetime


def _esc(value):
    return _html.escape(str(value if value is not None else ""))


def _score_color(total):
    if total >= 60:
        return "#ff6378"
    if total >= 30:
        return "#f4c95d"
    return "#45e6a5"


_CSS = """
body{font-family:Inter,Segoe UI,system-ui,sans-serif;background:#07100d;
     color:#edf5f1;margin:0}
.wrap{max-width:960px;margin:0 auto;padding:30px 24px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:#81948b;font-size:12px;margin-bottom:22px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
       gap:10px;margin-bottom:6px}
.tile{background:#0c1713;border:1px solid #1c3028;border-radius:10px;
      padding:14px 8px;text-align:center}
.tile b{display:block;font-size:22px;color:#45e6a5}
.tile span{font-size:10px;color:#81948b;letter-spacing:.5px}
.tile.score b{color:COLORPLACEHOLDER}
section{background:#0c1713;border:1px solid #1c3028;border-radius:12px;
        padding:18px 20px;margin-top:14px}
h2{font-size:13px;color:#45e6a5;text-transform:uppercase;letter-spacing:1px;
   margin:0 0 12px}
h3{font-size:12px;color:#b4c3bc;margin:14px 0 6px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{color:#81948b;font-size:10px;text-transform:uppercase;text-align:left;
   padding:7px 8px;border-bottom:1px solid #1c3028}
td{padding:7px 8px;border-bottom:1px solid #142219;color:#b4c3bc;
   font-family:Consolas,monospace}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:700px){.grid2{grid-template-columns:1fr}}
.bar-row{font-size:11px;margin-bottom:7px}
.bar-row .lbl{display:flex;justify-content:space-between;color:#9cacA5;
              margin-bottom:3px}
.bar{height:6px;background:#14241d;border-radius:6px;overflow:hidden}
.bar>i{display:block;height:100%;background:#45e6a5;border-radius:6px}
.con{background:#0a1511;border:1px solid #182e24;border-left:3px solid #f4c95d;
     padding:8px 11px;border-radius:6px;font-size:11px;color:#84958e;
     margin-bottom:6px}
.con b{color:#f4c95d;margin-right:6px}
.alert{background:#0a1511;border:1px solid #1c3028;border-left:3px solid #f4c95d;
       border-radius:8px;padding:13px 15px;margin-bottom:11px}
.alert.high{border-left-color:#ff6378}
.alert.medium{border-left-color:#f49b50}
.alert h4{margin:0;font-size:13px;color:#a9f0d1}
.alert .sev{font-size:9px;font-weight:800;padding:2px 7px;border-radius:3px;
            background:#54202a;color:#ffacba;margin-left:8px;vertical-align:middle}
.alert p{font-size:11px;color:#9cacA5;line-height:1.6;margin:7px 0 0}
.alert strong{color:#b4c3bc}
ul{margin:6px 0 2px 18px;padding:0}
li{font-size:11px;color:#84968e;line-height:1.65}
footer{color:#43574e;font-size:10px;text-align:center;margin-top:22px}
.sev-counts{display:flex;flex-wrap:wrap;align-content:center;gap:6px}
.cnt{display:inline-flex;align-items:center;gap:7px;background:#0a1511;
     border:1px solid #182e24;border-radius:6px;padding:6px 10px;font-size:11px;
     color:#9cacA5}
.cnt b{font-size:13px;color:#b4c3bc}
.cnt.critical b,.cnt.high b{color:#ff6378}
.cnt.medium b{color:#f49b50}
.cnt.low b{color:#f4c95d}
.cnt.info b{color:#81948b}
.sev.sev-critical{background:#4a1030;color:#ff9ec4}
.sev.sev-high{background:#54202a;color:#ffacba}
.sev.sev-medium{background:#4a3113;color:#f7c07a}
.sev.sev-low{background:#3d3613;color:#f4df8e}
.sev.sev-informational,.sev.sev-info{background:#1c2a24;color:#9cacA5}
.alert.low,.alert.informational{border-left-color:#f4c95d}
.alert.critical{border-left-color:#ff3b6b}
@media print{body{background:#fff;color:#111}section,.tile,.alert,.con{
    background:#fff;border-color:#ddd;color:#111}h1,h2,h3,td,li,p{color:#111}}
"""


def render_html(a, generated=None):
    """Return a standalone HTML report string for an analysis payload."""
    generated = generated or datetime.now()

    score = a.get("investigation_score") or {}
    total = int(score.get("total_score") or 0)
    alerts = a.get("alerts") or []
    color = _score_color(total)

    # severity counts + risk level for the executive summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for al in alerts:
        sev = str(al.get("severity", "informational")).lower()
        counts[sev if sev in counts else "informational"] += 1

    risk = "HIGH" if total >= 60 else ("MEDIUM" if total >= 30 else "LOW")
    risk_color = ("#ff6378" if risk == "HIGH"
                  else ("#f4c95d" if risk == "MEDIUM" else "#45e6a5"))

    devices = a.get("devices") or []
    devices_n = len(devices) if devices else int(a.get("active_hosts") or 0)
    duration = float(a.get("duration_seconds") or 0)
    rate = float(a.get("packets_per_second") or 0)

    summary_html = f"""
  <section>
    <h2>Security assessment summary</h2>
    <div class="grid2">
      <div>
        <table><tbody>
          <tr><td>Risk level</td><td><b style="color:{risk_color}">{risk}</b></td></tr>
          <tr><td>Packets analyzed</td><td><b>{int(a.get("packets_loaded") or 0):,}</b></td></tr>
          <tr><td>Devices observed</td><td><b>{devices_n}</b></td></tr>
          <tr><td>Alerts</td><td><b>{len(alerts)}</b></td></tr>
          {f'<tr><td>Capture duration</td><td><b>{duration:.1f}s</b></td></tr>' if duration else ''}
          {f'<tr><td>Average packet rate</td><td><b>{rate:.1f} pps</b></td></tr>' if rate else ''}
        </tbody></table>
      </div>
      <div class="sev-counts">
        <span class="cnt critical">Critical <b>{counts['critical']}</b></span>
        <span class="cnt high">High <b>{counts['high']}</b></span>
        <span class="cnt medium">Medium <b>{counts['medium']}</b></span>
        <span class="cnt low">Low <b>{counts['low']}</b></span>
        <span class="cnt info">Informational <b>{counts['informational']}</b></span>
      </div>
    </div>
  </section>"""

    # summary tiles
    tiles = [
        (str(a.get("packets_loaded", 0)), "PACKETS"),
        (str(a.get("unique_sources", 0)), "SOURCES"),
        (str(a.get("unique_destinations", 0)), "DESTINATIONS"),
        (str(len(alerts)), "ALERTS"),
        (str(total), "INVESTIGATION SCORE"),
    ]
    tiles_html = "".join(
        f'<div class="tile{" score" if lbl.startswith("INVESTIGATION") else ""}">'
        f"<b>{_esc(val)}</b><span>{_esc(lbl)}</span></div>"
        for val, lbl in tiles
    )

    # top talkers tables
    def _talkers(items):
        rows = "".join(
            f"<tr><td>{_esc(it.get('ip'))}</td><td>{_esc(it.get('count'))}</td></tr>"
            for it in (items or [])
        ) or '<tr><td colspan="2">No data</td></tr>'
        return ('<table><thead><tr><th>IP address</th><th>Packets</th></tr>'
                f"</thead><tbody>{rows}</tbody></table>")

    # protocol distribution bars
    dist = a.get("protocol_distribution") or {}
    proto_total = sum(dist.values()) or 1
    proto_html = "".join(
        f'<div class="bar-row"><div class="lbl"><span>{_esc(proto)}</span>'
        f"<span>{count} ({round(count / proto_total * 100)}%)</span></div>"
        f'<div class="bar"><i style="width:{round(count / proto_total * 100)}%"></i></div></div>'
        for proto, count in sorted(dist.items(), key=lambda x: -x[1])
    ) or '<p style="color:#81948b;font-size:11px">No data</p>'

    # score contributions
    cons = score.get("contributions") or []
    cons_html = "".join(
        f'<div class="con"><b>+{_esc(c.get("score"))}</b>'
        f"{_esc(c.get('label'))} — {_esc(c.get('reason'))}</div>"
        for c in cons
    ) or '<p style="color:#81948b;font-size:11px">No score contributions — traffic looks normal.</p>'

    # alerts
    alerts_html = ""
    for al in alerts:
        sev = str(al.get("severity", "medium"))
        benign = al.get("possible_benign_explanations") or []
        steps = al.get("suggested_investigation") or []
        conf = al.get("confidence") or 0
        mitre = al.get("mitre_technique") or ""
        windows = al.get("windows_matched") or 1

        who = f"Source: {_esc(al.get('source'))}"
        if al.get("destination"):
            who += f" → Target: {_esc(al.get('destination'))}"
        when = str(al.get("timestamp") or "")[:19].replace("T", " ")

        meta_bits = [f"<strong>Confidence:</strong> {int(conf)}%"]
        if mitre:
            meta_bits.append(f"<strong>MITRE ATT&amp;CK:</strong> {_esc(mitre)}")
        if windows > 1:
            meta_bits.append(f"<strong>Matched in:</strong> {windows} time windows")

        alerts_html += f"""
<div class="alert {sev.lower()}">
  <h4>{_esc(al.get("rule_name"))}<span class="sev sev-{sev.lower()}">{_esc(sev)}</span></h4>
  <p>{who} · <strong>Time:</strong> {_esc(when)}</p>
  <p>{' · '.join(meta_bits)}</p>
  <p><strong>Evidence:</strong> {_esc(al.get("evidence"))}</p>
  <p><strong>Why it matters:</strong> {_esc(al.get("why_it_matters"))}</p>
  {f"<p><strong>Possible benign causes:</strong></p><ul>{''.join(f'<li>{_esc(b)}</li>' for b in benign)}</ul>" if benign else ""}
  {f"<p><strong>Suggested investigation:</strong></p><ul>{''.join(f'<li>{_esc(s)}</li>' for s in steps)}</ul>" if steps else ""}
</div>"""
    if not alerts_html:
        alerts_html = '<p style="color:#81948b;font-size:11px">No alerts fired for this traffic.</p>'

    # compact detection table (detections at a glance)
    det_html = ""
    if alerts:
        det_rows = "".join(
            f"<tr><td>{_esc(al.get('rule_name'))}</td>"
            f"<td><span class=\"sev sev-{_esc(str(al.get('severity', 'info')).lower())}\">"
            f"{_esc(al.get('severity'))}</span></td>"
            f"<td>{int(al.get('confidence') or 0)}%</td>"
            f"<td>{_esc(al.get('mitre_technique') or '—')}</td>"
            f"<td>{_esc(al.get('evidence'))}</td></tr>"
            for al in alerts
        )
        det_html = (
            "<section><h2>Detections</h2>"
            "<table><thead><tr><th>Detection</th><th>Severity</th>"
            "<th>Confidence</th><th>MITRE ATT&amp;CK</th><th>Evidence</th></tr>"
            f"</thead><tbody>{det_rows}</tbody></table></section>"
        )

    source = a.get("filename") or "Captured traffic"
    warnings = a.get("warnings") or []
    warnings_html = (
        '<p style="color:#f4c95d;font-size:11px">Warning: '
        + _esc("; ".join(warnings)) + "</p>" if warnings else ""
    )

    css = _CSS.replace("COLORPLACEHOLDER", color)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetSentinel Report — {_esc(source)}</title>
<style>{css}</style>
</head>
<body>
<div class="wrap">
  <h1>NetSentinel Analysis Report</h1>
  <p class="sub">Source: <strong>{_esc(source)}</strong> &nbsp;·&nbsp;
     Generated: {_esc(generated.strftime("%Y-%m-%d %H:%M:%S"))} &nbsp;·&nbsp;
     Local-only — no data left this machine</p>
  <div class="tiles">{tiles_html}</div>
  {summary_html}
  {warnings_html}

  <section>
    <h2>Investigation score breakdown</h2>
    {cons_html}
  </section>

  <section>
    <h2>Traffic overview</h2>
    <div class="grid2">
      <div><h3>Top sources</h3>{_talkers(a.get("top_sources"))}</div>
      <div><h3>Top destinations</h3>{_talkers(a.get("top_destinations"))}</div>
    </div>
    <h3>Protocol distribution</h3>
    {proto_html}
    <p style="font-size:11px;color:#81948b;margin-top:10px">
      {f"Average packet size: <strong>{round(a.get('avg_packet_length') or 0)} bytes</strong> · " if a.get("avg_packet_length") else ""}
      {f"Most active source: <strong>{_esc(a.get('most_active_source'))}</strong>" if a.get("most_active_source") else ""}
    </p>
  </section>

  {det_html}

  <section>
    <h2>Alerts ({len(alerts)})</h2>
    {alerts_html}
  </section>

  <footer>NetSentinel — local network anomaly detection · report saved
          {generated.strftime("%Y-%m-%d %H:%M:%S")}</footer>
</div>
</body>
</html>"""


if __name__ == "__main__":
    demo = {
        "filename": "demo", "packets_loaded": 1, "unique_sources": 1,
        "unique_destinations": 1, "alerts": [],
        "investigation_score": {"total_score": 0, "contributions": []},
        "protocol_distribution": {"TCP": 1},
    }
    print("render_html OK,", len(render_html(demo)), "chars")

