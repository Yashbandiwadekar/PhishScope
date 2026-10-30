"""PhishScope rule engine - the detection core.

Every rule has an id, a plain-English reason and a point value. A name's score is the sum of the points of the rules
that fire (capped at 100) and maps to a risk level. The point values were written down from general phishing-analysis
knowledge BEFORE any evaluation data was looked at, and are NOT tuned on the test data (see evaluate_rules.py, which also
reports a data-learned weighting only as a comparison).

Inputs are plain values (name features, DNS / ASN / RDAP / InternetDB evidence, optional CT / Wayback), so the same rules run
on a single URL in the CLI, on a stream in the monitor, and on a whole table in the evaluation.
Passive only: no rule requires contacting the target.
"""
from dataclasses import dataclass
from typing import Callable

# TLDs that abuse-tracking organisations repeatedly list as heavily used by scammers (general knowledge; verified in the report)
RISKY_TLDS = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "click", "monster", "buzz", "rest", "work", "support", "cam", "sbs", "shop", "online", "site", "live"}
LEVELS = [(50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]


@dataclass(frozen=True)
class Rule:
    id: str
    group: str
    title: str
    reason: str
    points: int
    test: Callable[[dict], bool]


def _has(r, k):
    v = r.get(k)
    return v is not None and v == v            # not None / NaN


RULES = [
    # ---- the name itself --------------------------------------------------------------------------------------------------------
    Rule("N1", "name", "Looks like a misspelt brand", "within 1-2 edits of a very popular site's name, a classic typosquat", 25,
         lambda r: bool(r.get("brand_typosquat"))),
    Rule("N2", "name", "Contains a famous brand name", "the registered name embeds a well-known brand (brand + extra words)", 15,
         lambda r: bool(r.get("brand_contained"))),
    Rule("N3", "name", "Brand in the subdomain, not the registered name", "e.g. brand.login.example-site.com: the real owner of the name is not the brand", 25,
         lambda r: bool(r.get("brand_in_subdomain"))),
    Rule("N4", "name", "Credential/scam keywords in the name", "words such as login, verify, secure, wallet, claim, refund", 10,
         lambda r: r.get("n_suspicious_words", 0) >= 1),
    Rule("N5", "name", "Several scam keywords", "two or more such words in one name", 10,
         lambda r: r.get("n_suspicious_words", 0) >= 2),
    Rule("N6", "name", "Many hyphens", "three or more hyphens, typical of stuffed phishing names", 8,
         lambda r: r.get("n_hyphens", 0) >= 3),
    Rule("N7", "name", "Mostly digits or machine-generated look", "high digit share, or very random-looking letters", 8,
         lambda r: r.get("digit_ratio", 0) >= 0.3 or (r.get("entropy", 0) >= 3.5 and r.get("longest_consonant_run", 0) >= 5)),
    Rule("N8", "name", "Punycode / look-alike characters", "internationalised name that can hide look-alike letters", 10,
         lambda r: bool(r.get("is_punycode"))),
    Rule("N9", "name", "Frequently abused top-level domain", "TLDs that abuse trackers repeatedly list as popular with scammers", 8,
         lambda r: r.get("suffix", "") in RISKY_TLDS),
    Rule("N10", "name", "Free hosting / shared platform", "anyone can create a site on this platform; registry age tells nothing", 10,
         lambda r: bool(r.get("shared_platform"))),
    # ---- registry (RDAP) -------------------------------------------------------------------------------------------------------------
    Rule("R1", "registry", "Registered in the last 30 days", "most phishing names are used within days of registration", 30,
         lambda r: _has(r, "age_days") and 0 <= r["age_days"] < 30),
    Rule("R2", "registry", "Registered in the last 90 days", "young names are over-represented among phishing", 15,
         lambda r: _has(r, "age_days") and 30 <= r["age_days"] < 90),
    Rule("R3", "registry", "Registered in the last year", "weaker signal: a young name", 6,
         lambda r: _has(r, "age_days") and 90 <= r["age_days"] < 365),
    Rule("R4", "registry", "Registry hold / pending-delete status", "the registry or registrar has already flagged or frozen the name", 20,
         lambda r: bool(r.get("status_hold_or_lock"))),
    # ---- DNS & hosting ---------------------------------------------------------------------------------------------------------------
    Rule("D1", "dns", "No mail setup at all", "no MX, SPF or DMARC: nobody uses this name for normal business e-mail", 6,
         lambda r: _has(r, "dns_ok") and r.get("dns_ok") == 1 and r.get("mx_count", 0) == 0 and not r.get("has_spf") and not r.get("has_dmarc")),
    Rule("D2", "dns", "Very few DNS records", "an operated business domain normally has several TXT/verification records", 5,
         lambda r: _has(r, "dns_ok") and r.get("dns_ok") == 1 and r.get("txt_count", 0) == 0),
    Rule("D3", "dns", "Very low TTL", "records that change quickly can indicate fast-flux style hosting", 4,
         lambda r: _has(r, "ttl") and 0 <= r["ttl"] <= 120),
    Rule("D4", "dns", "Hosting IP exposes known vulnerabilities", "Shodan lists known CVEs for the server IP", 6,
         lambda r: r.get("n_vulns", 0) >= 1),
    Rule("D5", "dns", "No www host", "ordinary sites almost always also answer for www", 3,
         lambda r: _has(r, "dns_ok") and r.get("dns_ok") == 1 and _has(r, "has_www") and not r.get("has_www")),
    # ---- campaign link (graph) --------------------------------------------------------------------------------------------------------
    Rule("G1", "campaign", "Shares an IP with known phishing names", "the same server already hosts names from the phishing lists", 25,
         lambda r: r.get("shared_ip_known_phish", 0) >= 1),
    Rule("G2", "campaign", "Shares a rare name-server set with known phishing names", "same DNS infrastructure as listed phishing names", 15,
         lambda r: r.get("shared_ns_known_phish", 0) >= 1),
    # ---- optional deep evidence (slow public sources) --------------------------------------------------------------------------------
    Rule("C1", "deep", "First TLS certificate issued in the last 14 days", "certificate-transparency logs show a brand-new certificate", 12,
         lambda r: _has(r, "first_cert_age_days") and 0 <= r["first_cert_age_days"] < 14),
    Rule("C2", "deep", "Never archived by the Internet Archive", "no history at all suggests a brand-new site", 4,
         lambda r: r.get("wayback_archived") is False),
]
RULE_BY_ID = {r.id: r for r in RULES}


def evaluate(row):
    """returns (score, fired rules [(id, title, reason, points)], level)"""
    fired = [(r.id, r.title, r.reason, r.points) for r in RULES if r.test(row)]
    score = min(100, sum(p for *_, p in fired))
    level = next(name for cut, name in LEVELS if score >= cut)
    return score, fired, level


def score_table(df, use_groups=("name", "registry", "dns", "campaign")):
    """vectorised helper for evaluation: returns the score and the 0/1 fired-matrix for every row of a feature table"""
    import numpy as np
    import pandas as pd
    rules = [r for r in RULES if r.group in use_groups]
    M = np.zeros((len(df), len(rules)), dtype=np.int8)
    for i, row in enumerate(df.to_dict("records")):
        for j, r in enumerate(rules):
            M[i, j] = 1 if r.test(row) else 0
    pts = np.array([r.points for r in rules])
    return np.minimum(100, M @ pts), pd.DataFrame(M, columns=[r.id for r in rules])
