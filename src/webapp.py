"""PhishScope web page (Flask, localhost only).

  /            investigate form
  /investigate result page for one URL / domain (never contacts the target)
  /rules       all detection rules and their points
  /monitor     live-feed dashboard (reads outputs/monitor.db written by monitor.py)
"""
import html
import sqlite3
from pathlib import Path

import json
import random
import time

from flask import Flask, Response, jsonify, request, send_from_directory

import engine as E
import rules_engine as R

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "webapp"
app = Flask(__name__, static_folder=None)
_engine = None

CSS = """
:root{--bg:#ffffff;--fg:#1b2430;--muted:#5a6675;--line:#d9dee5;--card:#f6f8fa;--low:#2e7d4f;--med:#b7791f;--high:#c0392b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:14px 28px;border-bottom:1px solid var(--line);display:flex;gap:24px;align-items:baseline}
header b{font-size:20px}header a{color:var(--muted);text-decoration:none}header a:hover{color:var(--fg)}
main{max-width:1000px;margin:0 auto;padding:22px 28px 60px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0}
h2{font-size:16px;margin:0 0 8px}.muted{color:var(--muted)}code{background:#eef1f5;padding:1px 5px;border-radius:4px}
input[type=text]{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:8px;font-size:16px}
button{padding:10px 18px;border:0;border-radius:8px;background:#1f5fbf;color:#fff;font-size:15px;cursor:pointer;margin-top:10px}
.badge{display:inline-block;padding:3px 12px;border-radius:999px;color:#fff;font-weight:600}
.LOW{background:var(--low)}.MEDIUM{background:var(--med)}.HIGH{background:var(--high)}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;font-size:14px}
th{color:var(--muted);font-weight:600}.num{text-align:right;white-space:nowrap}
.bar{height:10px;background:#e3e8ee;border-radius:5px;overflow:hidden}.bar i{display:block;height:100%}
"""


def page(title, body):
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body>"
            f"<header><b>PhishScope</b><a href='/classic'>Investigate</a><a href='/classic/monitor'>Live monitor</a><a href='/classic/rules'>Rules</a>"
            f"<span class='muted'>passive OSINT screening - the target is never contacted</span></header><main>{body}</main></body></html>")


def d(s):
    return html.escape(str(s).replace(".", "[.]"))


def render_report(rep):
    t, ev = rep["target"], rep["evidence"]
    color = {"LOW": "#2e7d4f", "MEDIUM": "#b7791f", "HIGH": "#c0392b"}[rep["risk_level"]]
    rows = "".join(f"<tr><td class='num'>+{f['points']}</td><td><b>{html.escape(f['id'])}</b> {html.escape(f['title'])}<br><span class='muted'>{html.escape(f['reason'])}</span></td></tr>"
                   for f in rep["fired_rules"]) or "<tr><td colspan=2 class='muted'>No rule fired.</td></tr>"
    dns, rd, asn, idb = ev["dns"], ev["rdap"], ev.get("asn") or {}, ev.get("internetdb") or {}
    evrows = [("DNS", f"{dns.get('a_status')}; IPs {', '.join(dns.get('ips', [])[:3]) or '-'}; name servers {', '.join(dns.get('ns', [])[:2]) or '-'}; MX records {dns.get('mx_count', 0)}"),
              ("Hosting network", f"AS{asn.get('asn', '-')} {asn.get('as_name', '')} ({asn.get('cc', '-')})"),
              ("Registry (RDAP)", f"{rd.get('status')}; registered {str(rd.get('registered') or '-')[:10]}; age {rep['age_days'] if rep['age_days'] is not None else '-'} days; registrar {rd.get('registrar') or '-'}"),
              ("Shodan InternetDB", f"open ports {idb.get('ports', '-')}; known vulnerabilities {len(idb.get('vulns', [])) if idb else '-'}")]
    if "crtsh" in ev:
        evrows.append(("Certificate transparency", f"{ev['crtsh'].get('status')}; certificates {ev['crtsh'].get('cert_count', '-')}; first {ev['crtsh'].get('first_cert', '-')}"))
    if "wayback" in ev:
        evrows.append(("Internet Archive", f"{ev['wayback'].get('status')}; archived {ev['wayback'].get('archived', '-')}"))
    ev_html = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(str(v))}</td></tr>" for k, v in evrows)
    cm = rep["campaign"]
    camp = ""
    if cm["same_ip_known_phishing"] or cm["same_ns_set_known_phishing"]:
        camp = "<div class='card'><h2>Campaign link</h2>" + (f"<p>Same IP as known phishing names: {html.escape(', '.join(cm['same_ip_known_phishing']))}</p>" if cm["same_ip_known_phishing"] else "") + \
               (f"<p>Same name-server set: {html.escape(', '.join(cm['same_ns_set_known_phishing']))}</p>" if cm["same_ns_set_known_phishing"] else "") + "</div>"
    notes = "".join(f"<p class='muted'>Note: {html.escape(n)}</p>" for n in rep["notes"])
    return (f"<div class='card'><h2>{d(t['host'])}</h2><p class='muted'>registered name {d(t['reg'])}</p>"
            f"<p><span class='badge {rep['risk_level']}'>{rep['risk_level']}</span> &nbsp; <b>{rep['score']}</b> / 100 points "
            f"<span class='muted'>(LOW &lt; 25 &le; MEDIUM &lt; 50 &le; HIGH)</span></p>"
            f"<div class='bar'><i style='width:{rep['score']}%;background:{color}'></i></div></div>"
            f"<div class='card'><h2>Why: rules that fired</h2><table>{rows}</table></div>"
            f"<div class='card'><h2>Passive evidence</h2><table>{ev_html}</table></div>{camp}{notes}"
            f"<p class='muted'>{html.escape(rep['caveat'])} Analysis took {rep['seconds']} s.</p>")


@app.route("/classic")
def index():
    return page("PhishScope", "<div class='card'><h2>Investigate a URL or domain</h2><form action='/classic/investigate' method='post'>"
                "<input type='text' name='target' placeholder='e.g. https://secure-login.example-bank.top/verify' autofocus>"
                "<label class='muted'><input type='checkbox' name='deep' value='1'> also query certificate-transparency logs and the Internet Archive (slower)</label><br>"
                "<button type='submit'>Investigate</button></form></div>"
                "<p class='muted'>PhishScope looks only at public records about the name (DNS, registry, hosting network, certificate and archive history). "
                "It never opens the page you give it.</p>")


@app.route("/classic/investigate", methods=["POST"])
def investigate():
    global _engine
    _engine = _engine or E.Engine()
    target = request.form.get("target", "")
    try:
        rep = _engine.investigate(target, deep=bool(request.form.get("deep")))
    except ValueError as e:
        return page("PhishScope", f"<div class='card'><h2>Cannot analyse that input</h2><p>{html.escape(str(e))}</p><a href='/'>Back</a></div>")
    return page("PhishScope report", render_report(rep))


@app.route("/classic/rules")
def rules():
    rows = "".join(f"<tr><td>{r.id}</td><td>{r.group}</td><td class='num'>{r.points}</td><td><b>{html.escape(r.title)}</b><br><span class='muted'>{html.escape(r.reason)}</span></td></tr>" for r in R.RULES)
    return page("PhishScope rules", f"<div class='card'><h2>Detection rules</h2><p class='muted'>Score = sum of the points of the rules that fire (max 100). "
                f"LOW &lt; 25 &le; MEDIUM &lt; 50 &le; HIGH. Points were set from security knowledge before any evaluation.</p>"
                f"<table><tr><th>ID</th><th>Group</th><th class='num'>Points</th><th>Rule</th></tr>{rows}</table></div>")


@app.route("/classic/monitor")
def monitor():
    p = ROOT / "outputs" / "monitor.db"
    if not p.exists():
        return page("Monitor", "<div class='card'>No monitor data yet. Run <code>python phishscope.py monitor</code>.</div>")
    con = sqlite3.connect(p)
    total = con.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
    lv = dict(con.execute("SELECT level, COUNT(*) FROM seen GROUP BY level").fetchall())
    lat = con.execute("SELECT AVG(latency_s), MAX(latency_s) FROM seen WHERE latency_s IS NOT NULL").fetchone()
    rows = con.execute("SELECT host, source, first_seen_utc, score, level, rules, resolves, age_days, latency_s FROM seen WHERE level IN ('HIGH','MEDIUM') "
                       "ORDER BY first_seen_utc DESC, score DESC LIMIT 25").fetchall()
    body = (f"<div class='card'><h2>Live feed monitor</h2><p>{total} names scored. HIGH {lv.get('HIGH', 0)}, MEDIUM {lv.get('MEDIUM', 0)}, LOW {lv.get('LOW', 0)}. "
            f"Mean time to verdict {lat[0] or 0:.1f} s (max {lat[1] or 0:.1f} s) per name, from feed arrival to score.</p></div>"
            "<div class='card'><h2>Latest alerts (names defanged)</h2><table><tr><th>Name</th><th>Source</th><th class='num'>Score</th><th>Level</th><th>Rules</th><th class='num'>Age (d)</th><th class='num'>Secs</th></tr>"
            + "".join(f"<tr><td>{d(h)}</td><td>{html.escape(s)}</td><td class='num'>{sc}</td><td><span class='badge {l}'>{l}</span></td><td>{html.escape(r or '')}</td>"
                      f"<td class='num'>{'-' if a is None else round(a)}</td><td class='num'>{la:.1f}</td></tr>" for h, s, ts, sc, l, r, rs, a, la in rows)
            + "</table></div>")
    return page("PhishScope monitor", body)


# ====================================================================== single-page app + JSON API
OUT = ROOT / "outputs"
_cache = {}


def jload(name):
    p = OUT / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


@app.route("/")
def spa():
    return send_from_directory(STATIC, "index.html")


@app.route("/static/<path:name>")
def static_files(name):
    return send_from_directory(STATIC, name)


def _engine_get():
    global _engine
    _engine = _engine or E.Engine()
    return _engine


@app.route("/api/investigate_stream")
def api_stream():
    target = request.args.get("target", "")
    deep = request.args.get("deep") == "1"

    def gen():
        try:
            for ev, data in _engine_get().investigate_stream(target, deep=deep):
                yield f"event: {ev}\ndata: {json.dumps(data, default=str)}\n\n"
        except ValueError as e:
            yield f"event: fail\ndata: {json.dumps({'message': str(e)})}\n\n"
        except Exception as e:  # noqa: BLE001
            yield f"event: fail\ndata: {json.dumps({'message': 'analysis failed: ' + type(e).__name__})}\n\n"
    return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/rules")
def api_rules():
    return jsonify([{"id": r.id, "group": r.group, "title": r.title, "reason": r.reason, "points": r.points} for r in R.RULES])


@app.route("/api/monitor")
def api_monitor():
    p = OUT / "monitor.db"
    if not p.exists():
        return jsonify({"rows": [], "stats": {"total": 0}})
    con = sqlite3.connect(p)
    rows = con.execute("SELECT host, source, first_seen_utc, score, level, rules, resolves, age_days, latency_s, shared_platform FROM seen "
                       "ORDER BY first_seen_utc DESC, score DESC LIMIT 600").fetchall()
    total = con.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
    lv = dict(con.execute("SELECT level, COUNT(*) FROM seen GROUP BY level").fetchall())
    by_src = dict(con.execute("SELECT source, COUNT(*) FROM seen GROUP BY source").fetchall())
    lat = con.execute("SELECT AVG(latency_s), MAX(latency_s) FROM seen WHERE latency_s IS NOT NULL").fetchone()
    tl = con.execute("SELECT substr(first_seen_utc, 12, 5) AS t, COUNT(*), SUM(level='HIGH'), SUM(level='MEDIUM') FROM seen GROUP BY first_seen_utc ORDER BY first_seen_utc").fetchall()
    return jsonify({"stats": {"total": total, "levels": lv, "sources": by_src, "latency_mean": lat[0], "latency_max": lat[1]},
                    "timeline": [{"t": a, "n": b, "high": c, "medium": d} for a, b, c, d in tl],
                    "rows": [dict(host=h, source=s_, seen=ts, score=sc, level=lvl, rules=(r or "").split(",") if r else [], resolves=rs, age=a, latency=la, shared=sh)
                             for h, s_, ts, sc, lvl, r, rs, a, la, sh in rows]})


@app.route("/api/sample")
def api_sample():
    p = OUT / "monitor.db"
    if not p.exists():
        return jsonify({"host": None})
    con = sqlite3.connect(p)
    rows = [r[0] for r in con.execute("SELECT host FROM seen WHERE level IN ('HIGH','MEDIUM') AND resolves=1 ORDER BY RANDOM() LIMIT 20")]
    return jsonify({"host": random.choice(rows) if rows else None})


@app.route("/favicon.ico")
def favicon():
    svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><circle cx='16' cy='16' r='11' fill='none' stroke='#1f5fbf' stroke-width='4'/><circle cx='26' cy='26' r='5' fill='#c0392b'/></svg>"
    return Response(svg, mimetype="image/svg+xml")


def _json_safe(obj):
    """Python's json writes NaN/Infinity, which browsers cannot parse - turn them into null."""
    import re
    return Response(re.sub(r"(?<![\w\"])-?(NaN|Infinity)(?![\w\"])", "null", json.dumps(obj, default=float)), mimetype="application/json")


@app.route("/api/results")
def api_results():
    return _json_safe({"rules": jload("results_rules.json"), "enriched": jload("results_enriched.json"), "lexical": jload("results_lexical.json"),
                    "graph": jload("graph_summary.json"), "graph_specific": jload("graph_summary_specific.json"), "dataset": json.loads((ROOT / "data" / "processed" / "dataset_summary.json").read_text())})


@app.route("/api/ruleslab")
def api_ruleslab():
    return jsonify(jload("ruleslab.json"))


@app.route("/api/graph")
def api_graph():
    if "graph" in _cache:
        return jsonify(_cache["graph"])
    import graph_corr as G
    import pandas as pd
    import networkx as nx
    G.W = {"ip": 3, "prefix24": 0, "nsset": 2, "bulkreg": 0}
    mem = pd.read_csv(OUT / "graph_membership_specific.csv")
    label = dict(zip(mem.reg, mem.label))
    attrs = G.attributes(mem.reg.tolist())
    Gr, _, _ = G.build_graph(attrs)
    comms = [c for c in nx.community.louvain_communities(Gr, weight="weight", seed=42) if len(c) >= 3]
    comms.sort(key=len, reverse=True)
    clusters, nodes, edges, keep = [], [], [], set()
    for i, c in enumerate(comms[:14]):
        ph = sum(label[r] for r in c)
        clusters.append({"id": i + 1, "size": len(c), "phishing": ph, "share": ph / len(c)})
        for r in c:
            if len(keep) < 520:
                keep.add(r)
    ids = {}
    for i, c in enumerate(comms[:14]):
        for r in c:
            if r in keep:
                a = attrs[r]
                nodes.append({"id": r, "label": int(label[r]), "cluster": i + 1, "ips": a["ips"][:2], "ns": list(a["ns"][:2]), "registrar": a["registrar"]})
                ids[r] = len(nodes) - 1
    for a, b, d in Gr.edges(data=True):
        if a in ids and b in ids:
            edges.append({"s": ids[a], "t": ids[b], "w": d["weight"], "types": sorted(d["types"])})
    _cache["graph"] = {"clusters": clusters, "nodes": nodes, "edges": edges}
    return jsonify(_cache["graph"])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
