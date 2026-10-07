"""Standalone HTML report renderer."""
import html, json

def render_html(data):
    d=data or {}; score=d.get("investigation_score") or {}; alerts=d.get("alerts") or []
    title=html.escape(str(d.get("filename","NetSentinel Report")))
    cards=f'''<div class="grid"><div>Packets<strong>{d.get("packets_loaded",0)}</strong></div><div>Sources<strong>{d.get("unique_sources",0)}</strong></div><div>Destinations<strong>{d.get("unique_destinations",0)}</strong></div><div>Score<strong>{score.get("total_score",0)}</strong></div></div>'''
    alert_html="".join(f'<article><b>{html.escape(str(a.get("rule_name","Alert")))}</b> <span>{html.escape(str(a.get("severity","")))}</span><p>{html.escape(str(a.get("evidence","")))}</p><small>{html.escape(str(a.get("why_it_matters","")))}</small></article>' for a in alerts) or '<p>No alerts detected.</p>'
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>NetSentinel Report — {title}</title><style>body{{font-family:system-ui;margin:40px;max-width:1100px}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.grid>div,article{{border:1px solid #ddd;border-radius:10px;padding:18px;margin:10px 0}}strong{{display:block;font-size:28px;margin-top:8px}}span{{float:right}}@media(max-width:700px){{.grid{{grid-template-columns:1fr 1fr}}}}</style></head><body><h1>NetSentinel Network Analysis</h1><p>Source: {title}</p>{cards}<h2>Analysis</h2><p>{html.escape(str(score.get("summary","")))}</p><h2>Alerts</h2>{alert_html}<h2>Top Sources</h2><pre>{html.escape(json.dumps(d.get("top_sources",[]),indent=2))}</pre><h2>Top Destinations</h2><pre>{html.escape(json.dumps(d.get("top_destinations",[]),indent=2))}</pre></body></html>'''
