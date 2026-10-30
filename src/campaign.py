"""Campaign matching: does a name share rare infrastructure with names already known to be phishing?

Reference set = the graph sample (4,000 phishing-list names + 2,000 benign names, DNS-enriched). An IP or name-server set only
counts as evidence when it is SPECIFIC: at most MAX_GROUP reference names use it and at least MIN_PHISH_SHARE of them are
phishing names. Big shared hosts / CDNs therefore never create a match (they carry plenty of benign names too).
"""
from collections import defaultdict
from pathlib import Path

import pandas as pd

import collectors as C

ROOT = Path(__file__).resolve().parents[1]
MAX_GROUP = 15
MIN_PHISH_SHARE = 0.6
_idx = None


def _index():
    global _idx
    if _idx is None:
        s = pd.read_csv(ROOT / "data" / "processed" / "graph_sample.csv")
        ip_g, ns_g = defaultdict(list), defaultdict(list)
        for r in s.itertuples():
            d = C.cache_get("dns", r.reg)
            if not d or d.get("a_status") != "ok":
                continue
            for ip in d.get("ips", []):
                ip_g[ip].append((r.reg, int(r.label)))
            if d.get("ns"):
                ns_g[tuple(d["ns"])].append((r.reg, int(r.label)))
        _idx = (ip_g, ns_g)
    return _idx


def _specific(group):
    if not group or len(group) > MAX_GROUP:
        return []
    ph = [n for n, l in group if l == 1]
    return ph if len(ph) / len(group) >= MIN_PHISH_SHARE else []


def match(reg, ips, ns):
    ip_g, ns_g = _index()
    ip_hits, ns_hits = set(), set()
    for ip in ips or []:
        ip_hits.update(n for n in _specific(ip_g.get(ip)) if n != reg)
    if ns:
        ns_hits.update(n for n in _specific(ns_g.get(tuple(ns))) if n != reg)
    return sorted(ip_hits), sorted(ns_hits)


def features(reg):
    d = C.cache_get("dns", reg) or {}
    ip_hits, ns_hits = match(reg, d.get("ips", []), d.get("ns", []))
    return {"shared_ip_known_phish": len(ip_hits), "shared_ns_known_phish": len(ns_hits)}
