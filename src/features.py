"""Feature extraction for PhishScope.

Lexical features use ONLY the registered name (eTLD+1) so that benign names (Tranco lists registered names, never
subdomains) and phishing names are described the same way. Subdomain-level signals are handled by the rule layer of
the investigator, not by the evaluated model.

Network features come from the passive-collector cache (DNS, hosting ASN, RDAP registration data).
"""
import io
import math
import re
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import tldextract
from rapidfuzz import process
from rapidfuzz.distance import Levenshtein

import collectors as C

ROOT = Path(__file__).resolve().parents[1]

# words that scam / credential-harvesting pages commonly put in names (fixed list, written independently of the dataset)
SUSPICIOUS_WORDS = [
    "login", "signin", "secure", "verify", "verification", "account", "update", "support", "wallet", "claim", "bonus", "confirm",
    "payment", "service", "official", "alert", "auth", "webmail", "recover", "unlock", "billing", "invoice", "refund", "prize",
    "gift", "airdrop", "metamask", "crypto", "banking", "customer", "helpdesk", "password", "validate", "suspend", "limited",
    "free", "reward", "survey", "delivery", "tracking", "parcel", "kyc", "pan", "aadhaar", "upi",
]
VOWELS = set("aeiou")
_EXTRACT = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=())


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def longest_run(s, pred):
    best = cur = 0
    for ch in s:
        cur = cur + 1 if pred(ch) else 0
        best = max(best, cur)
    return best


def load_brands(n=500, min_len=5):
    """Brand labels = labels of the top-ranked Tranco names (popular names are the ones worth impersonating)."""
    raw = sorted((ROOT / "data" / "raw").glob("20*"))[-1]
    with zipfile.ZipFile(raw / "tranco_top1m.csv.zip") as z:
        tr = pd.read_csv(io.TextIOWrapper(z.open(z.namelist()[0]), encoding="utf-8"), names=["rank", "host"], header=None, nrows=n * 3)
    labels = []
    for h in tr["host"].str.lower():
        e = _EXTRACT(h)
        lab = e.domain
        if len(lab) >= min_len and lab.isalpha() and lab not in labels:
            labels.append(lab)
        if len(labels) >= n:
            break
    return labels


def label_of(reg):
    e = _EXTRACT(reg)
    return e.domain, e.suffix


def lexical_frame(regs, brands):
    rows = []
    for reg in regs:
        lab, suffix = label_of(reg)
        parts = [p for p in re.split(r"[-_]", lab) if p]
        letters = [c for c in lab if c.isalpha()]
        vowel_share = sum(c in VOWELS for c in letters) / max(len(letters), 1)
        contains = next((b for b in brands if b in lab and b != lab), None)
        hit = process.extractOne(lab, brands, scorer=Levenshtein.distance)
        dist = hit[1] if hit else 99
        near = hit[0] if hit else None
        rows.append({
            "len_label": len(lab),
            "n_digits": sum(c.isdigit() for c in lab),
            "digit_ratio": sum(c.isdigit() for c in lab) / max(len(lab), 1),
            "n_hyphens": lab.count("-"),
            "n_parts": len(parts),
            "max_part_len": max((len(p) for p in parts), default=0),
            "entropy": entropy(lab),
            "vowel_share": vowel_share,
            "longest_consonant_run": longest_run(lab, lambda c: c.isalpha() and c not in VOWELS),
            "longest_digit_run": longest_run(lab, str.isdigit),
            "unique_char_ratio": len(set(lab)) / max(len(lab), 1),
            "is_punycode": int(lab.startswith("xn--")),
            "n_suspicious_words": sum(w in lab for w in SUSPICIOUS_WORDS),
            "brand_contained": int(contains is not None),
            "brand_edit_distance": min(dist, 10),
            "brand_typosquat": int(0 < dist <= 2 and len(lab) >= 5),
            "suffix": suffix,
            "label": lab,
        })
    return pd.DataFrame(rows)


NUMERIC_LEXICAL = ["len_label", "n_digits", "digit_ratio", "n_hyphens", "n_parts", "max_part_len", "entropy", "vowel_share",
                   "longest_consonant_run", "longest_digit_run", "unique_char_ratio", "is_punycode", "n_suspicious_words"]
BRAND_FEATS = ["brand_contained", "brand_edit_distance", "brand_typosquat"]


# ------------------------------------------------------------------------------------------------ network features (from cache)
def _provider(ns_list):
    if not ns_list:
        return "none"
    e = _EXTRACT(ns_list[0])
    return f"{e.domain}.{e.suffix}"


def network_frame(regs):
    rows = []
    for reg in regs:
        dns_r = C.cache_get("dns", reg) or {}
        ips = dns_r.get("ips", [])
        asn = (C.cache_get("asn", ips[0]) or {}) if ips else {}
        idb = (C.cache_get("internetdb", ips[0]) or {}) if ips else {}
        dx = C.cache_get("dnsx", reg) or {}
        rd = C.cache_get("rdap", reg) or {}
        age = C.age_days(rd.get("registered")) if rd.get("status") == "ok" else None
        exp = C.age_days(rd.get("expires")) if rd.get("status") == "ok" else None
        chg = C.age_days(rd.get("changed")) if rd.get("status") == "ok" else None
        reg_len = None
        if rd.get("registered") and rd.get("expires"):
            a, b = C.age_days(rd["registered"]), C.age_days(rd["expires"])
            reg_len = (a - b) if a is not None and b is not None else None
        statuses = " ".join(rd.get("domain_status", []))
        rows.append({
            "reg": reg,
            "dns_ok": int(dns_r.get("a_status") == "ok"),
            "n_ips": len(ips),
            "ttl": dns_r.get("ttl") if dns_r.get("ttl") is not None else -1,
            "ns_count": len(dns_r.get("ns", [])),
            "ns_provider": _provider(dns_r.get("ns", [])),
            "mx_count": dns_r.get("mx_count", 0),
            "has_spf": int(bool(dns_r.get("has_spf"))),
            "txt_count": dns_r.get("txt_count", 0),
            "has_dmarc": int(bool(dx.get("has_dmarc"))),
            "has_www": int(bool(dx.get("has_www"))),
            "has_caa": int(bool(dx.get("has_caa"))),
            "n_ports": len(idb.get("ports", [])),
            "port_80": int(80 in idb.get("ports", [])),
            "port_443": int(443 in idb.get("ports", [])),
            "port_22": int(22 in idb.get("ports", [])),
            "n_vulns": len(idb.get("vulns", [])),
            "n_ip_hostnames": len(idb.get("hostnames", [])),
            "idb_cloud_tag": int("cloud" in idb.get("tags", [])),
            "asn": asn.get("asn") or "none",
            "asn_cc": asn.get("cc") or "none",
            "rdap_ok": int(rd.get("status") == "ok"),
            "rdap_status": rd.get("status", "missing"),
            "age_days": age if age is not None else -1,
            "expires_in_days": -exp if exp is not None else -1,
            "days_since_change": chg if chg is not None else -1,
            "registration_years": (reg_len / 365.25) if reg_len is not None else -1,
            "registrar": rd.get("registrar") or "none",
            "dnssec": int(bool(rd.get("dnssec"))),
            "status_hold_or_lock": int(any(k in statuses.lower() for k in ("hold", "pending"))),
        })
    return pd.DataFrame(rows)


DNS_FEATS = ["n_ips", "ttl", "ns_count", "mx_count", "has_spf", "txt_count", "has_dmarc", "has_www", "has_caa"]
HOST_NUM = ["n_ports", "port_80", "port_443", "port_22", "n_vulns", "n_ip_hostnames", "idb_cloud_tag"]
HOST_CATS = ["ns_provider", "asn", "asn_cc"]
RDAP_NUM = ["rdap_ok", "age_days", "expires_in_days", "days_since_change", "registration_years", "dnssec", "status_hold_or_lock"]
RDAP_CATS = ["registrar"]
