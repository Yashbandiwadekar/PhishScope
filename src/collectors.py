"""Passive OSINT collectors used by PhishScope. None of them sends a request to the domain under investigation.

  dns_lookup   - A / NS / MX / TXT(SPF) through public resolvers (1.1.1.1, 8.8.8.8)           -> the domain's DNS records
  asn_lookup   - Team Cymru IP-to-ASN mapping, which is itself a DNS query                        -> hosting network
  rdap_lookup  - registration data from the TLD registry via the IANA RDAP bootstrap (RFC 7484/9224) -> age, registrar, status
  internetdb   - Shodan InternetDB (passive database lookup by IP)                                -> open ports, hostnames, CVEs
  crtsh_lookup - certificate-transparency logs (crt.sh)                                           -> certificates issued for the name
  wayback_first_seen - Internet Archive availability API                                            -> was the name ever archived?

All results are cached in SQLite (data/processed/cache.db), so repeated runs are free and every number in the report
can be traced to a stored record.
"""
import ipaddress
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver
import requests

ROOT = Path(__file__).resolve().parents[1]
CACHE_PATH = ROOT / "data" / "processed" / "cache.db"
UA = {"User-Agent": "PhishScope-student-miniproject/1.0 (academic research; passive lookups only)"}

_lock = threading.Lock()
_db = None


def db():
    global _db
    if _db is None:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _db = sqlite3.connect(CACHE_PATH, check_same_thread=False)
        _db.execute("CREATE TABLE IF NOT EXISTS cache (kind TEXT, key TEXT, value TEXT, ts REAL, PRIMARY KEY (kind, key))")
        _db.commit()
    return _db


def cache_get(kind, key):
    with _lock:
        r = db().execute("SELECT value FROM cache WHERE kind=? AND key=?", (kind, key)).fetchone()
    return json.loads(r[0]) if r else None


def cache_put(kind, key, value):
    with _lock:
        db().execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)", (kind, key, json.dumps(value), time.time()))
        db().commit()


def cached(kind):
    def deco(fn):
        def wrapper(key, *a, use_cache=True, **kw):
            if use_cache:
                hit = cache_get(kind, key)
                if hit is not None:
                    return hit
            val = fn(key, *a, **kw)
            if val is not None and not (isinstance(val, dict) and val.get("_transient")):
                cache_put(kind, key, val)
            return val
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


# ------------------------------------------------------------------------------------------------ DNS
def _resolver():
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ["1.1.1.1", "8.8.8.8"]
    r.timeout, r.lifetime = 3.0, 6.0
    return r


def _q(res, name, rtype):
    """returns (status, answers): status is ok / nxdomain / noanswer / error"""
    try:
        ans = res.resolve(name, rtype, raise_on_no_answer=True)
        return "ok", ans
    except dns.resolver.NXDOMAIN:
        return "nxdomain", None
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return "noanswer", None
    except (dns.exception.Timeout, dns.exception.DNSException):
        return "error", None


@cached("dns")
def dns_lookup(name):
    res = _resolver()
    out = {"name": name}
    st, a = _q(res, name, "A")
    out["a_status"] = st
    out["ips"] = sorted({r.address for r in a}) if a else []
    out["ttl"] = a.rrset.ttl if a else None
    _, ns = _q(res, name, "NS")
    out["ns"] = sorted(str(r.target).rstrip(".").lower() for r in ns) if ns else []
    _, mx = _q(res, name, "MX")
    out["mx_count"] = len(mx) if mx else 0
    _, txt = _q(res, name, "TXT")
    texts = [b"".join(r.strings).decode("utf-8", "ignore") for r in txt] if txt else []
    out["has_spf"] = any(t.lower().startswith("v=spf1") for t in texts)
    out["txt_count"] = len(texts)
    if out["a_status"] == "error" and not out["ns"]:
        out["_transient"] = True            # timeouts are not cached as facts
    return out


@cached("asn")
def asn_lookup(ip):
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    res = _resolver()
    rev = ".".join(reversed(ip.split(".")))
    st, a = _q(res, f"{rev}.origin.asn.cymru.com", "TXT")
    if not a:
        return {"ip": ip, "asn": None}
    fields = [f.strip() for f in b"".join(a[0].strings).decode().split("|")]
    out = {"ip": ip, "asn": fields[0].split()[0], "prefix": fields[1], "cc": fields[2], "registry": fields[3]}
    st, n = _q(res, f"AS{out['asn']}.asn.cymru.com", "TXT")
    if n:
        parts = [f.strip() for f in b"".join(n[0].strings).decode().split("|")]
        out["as_name"] = parts[-1] if parts else ""
    return out


@cached("dnsx")
def dns_extras(name):
    """DMARC policy record, www host and CAA records - cheap passive DNS signals of an operated, maintained domain."""
    res = _resolver()
    out = {"name": name}
    _, d = _q(res, f"_dmarc.{name}", "TXT")
    out["has_dmarc"] = bool(d and any(b"".join(r.strings).decode("utf-8", "ignore").lower().startswith("v=dmarc1") for r in d))
    st, w = _q(res, f"www.{name}", "A")
    out["has_www"] = bool(w)
    _, caa = _q(res, name, "CAA")
    out["has_caa"] = bool(caa)
    if st == "error":
        out["_transient"] = True
    return out


# ------------------------------------------------------------------------------------------------ RDAP
_bootstrap = None
_rdap_sem = {}
_rdap_last = {}


def _rdap_bases():
    global _bootstrap
    if _bootstrap is None:
        hit = cache_get("rdap_bootstrap", "dns")
        if hit is None:
            hit = requests.get("https://data.iana.org/rdap/dns.json", headers=UA, timeout=30).json()
            cache_put("rdap_bootstrap", "dns", hit)
        m = {}
        for tlds, urls in hit["services"]:
            for t in tlds:
                m[t.lower()] = urls[0]
        _bootstrap = m
    return _bootstrap


def _event(events, action):
    for e in events or []:
        if e.get("eventAction") == action:
            return e.get("eventDate")
    return None


@cached("rdap")
def rdap_lookup(reg):
    tld = reg.rsplit(".", 1)[-1].lower()
    base = _rdap_bases().get(tld)
    if not base:
        return {"reg": reg, "status": "no_rdap_for_tld"}
    sem = _rdap_sem.setdefault(base, threading.Semaphore(3))
    url = base.rstrip("/") + "/domain/" + reg.encode("idna").decode()
    for attempt in range(4):
        with sem:
            gap = time.time() - _rdap_last.get(base, 0)
            if gap < 0.35:
                time.sleep(0.35 - gap)
            _rdap_last[base] = time.time()
            try:
                r = requests.get(url, headers={**UA, "Accept": "application/rdap+json"}, timeout=20)
            except requests.RequestException:
                time.sleep(2 * (attempt + 1))
                continue
        if r.status_code == 429:
            time.sleep(5 * (attempt + 1))
            continue
        if r.status_code == 404:
            return {"reg": reg, "status": "not_found"}
        if r.status_code != 200:
            return {"reg": reg, "status": f"http_{r.status_code}", "_transient": r.status_code >= 500}
        j = r.json()
        ev = j.get("events", [])
        registrar = None
        for ent in j.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item[0] == "fn":
                        registrar = item[3]
        out = {"reg": reg, "status": "ok", "registered": _event(ev, "registration"), "expires": _event(ev, "expiration"),
               "changed": _event(ev, "last changed"), "registrar": registrar, "domain_status": j.get("status", []),
               "ns": sorted(n.get("ldhName", "").lower() for n in j.get("nameservers", [])),
               "dnssec": bool((j.get("secureDNS") or {}).get("delegationSigned"))}
        return out
    return {"reg": reg, "status": "failed", "_transient": True}


def age_days(iso):
    if not iso:
        return None
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - d).total_seconds() / 86400
    except ValueError:
        return None


# ------------------------------------------------------------------------------------------------ other passive sources
@cached("internetdb")
def internetdb(ip):
    r = requests.get(f"https://internetdb.shodan.io/{ip}", headers=UA, timeout=15)
    if r.status_code == 404:
        return {"ip": ip, "ports": [], "vulns": [], "hostnames": [], "note": "no data"}
    r.raise_for_status()
    j = r.json()
    return {"ip": ip, "ports": j.get("ports", []), "vulns": j.get("vulns", []), "hostnames": j.get("hostnames", []), "tags": j.get("tags", [])}


@cached("crtsh")
def crtsh_lookup(name):
    r = requests.get("https://crt.sh/", params={"q": name, "output": "json"}, headers=UA, timeout=45)
    if r.status_code != 200:
        return {"name": name, "status": f"http_{r.status_code}", "_transient": True}
    rows = r.json()
    issued = sorted({x.get("not_before", "")[:10] for x in rows if x.get("not_before")})
    issuers = sorted({x.get("issuer_name", "") for x in rows})
    names = sorted({n for x in rows for n in x.get("name_value", "").split("\n")})
    return {"name": name, "status": "ok", "cert_count": len(rows), "first_cert": issued[0] if issued else None,
            "last_cert": issued[-1] if issued else None, "issuers": issuers[:5], "names_sample": names[:25], "names_count": len(names)}


@cached("wayback")
def wayback_first_seen(name):
    r = requests.get("https://archive.org/wayback/available", params={"url": name, "timestamp": "19960101"}, headers=UA, timeout=25)
    if r.status_code != 200:
        return {"name": name, "status": f"http_{r.status_code}", "_transient": True}
    snap = r.json().get("archived_snapshots", {}).get("closest")
    return {"name": name, "status": "ok", "archived": bool(snap), "first_snapshot": snap.get("timestamp") if snap else None}
