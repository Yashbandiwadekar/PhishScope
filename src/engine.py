"""PhishScope investigation engine (shared by the CLI, the monitor and the web page).

Verdict = rule engine (rules_engine.py): transparent weighted rules over passive evidence. The machine-learning models are optional
and shown only as a labelled "statistical second opinion"; they never change the verdict.

Passive only: the target is never contacted. Evidence = the name itself + DNS records + hosting network (ASN) + registry data (RDAP)
+ Shodan InternetDB + campaign match against known phishing infrastructure + (optional, slow) certificate-transparency and Internet
Archive history.
"""
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import tldextract

import campaign
import collectors as C
import features as F
import rules_engine as R

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "models"
_EXTRACT = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=())
HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PATH_WORDS = ["login", "signin", "verify", "account", "update", "secure", "password", "wallet", "confirm", "bank", "payment", "otp", "kyc"]


def refang(text):
    """accept the standard security 'defanged' notation, e.g. hxxps://name[.]example"""
    return text.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://")


def parse_target(text):
    t = refang(text.strip())
    if "://" not in t:
        t = "http://" + t
    sp = urlsplit(t)
    host = (sp.hostname or "").lower().rstrip(".")
    if not host or IP_RE.match(host) or not HOST_RE.match(host):
        raise ValueError("please give a URL or a domain name (IP addresses are not supported)")
    e = _EXTRACT(host)
    reg = f"{e.domain}.{e.suffix}" if e.suffix else e.domain
    return {"input": text.strip(), "host": host, "reg": reg, "suffix": e.suffix, "subdomain": e.subdomain, "shared_platform": bool(e.is_private),
            "path": (sp.path or "") + (("?" + sp.query) if sp.query else "")}


def defang(s):
    return s.replace("http", "hxxp").replace(".", "[.]")


class Engine:
    def __init__(self, with_ml=False):
        self.brands = F.load_brands()
        self.ml = None
        if with_ml and (MODELS / "enriched_model.joblib").exists():
            import joblib
            self.ml = {"lex": joblib.load(MODELS / "lexical_model.joblib"), "enr": joblib.load(MODELS / "enriched_model.joblib")}

    # ------------------------------------------------------------------ evidence (passive)
    def collect(self, reg, deep=False):
        t0 = time.time()
        ev = {"dns": C.dns_lookup(reg), "rdap": C.rdap_lookup(reg), "dnsx": C.dns_extras(reg)}
        ips = ev["dns"].get("ips", [])
        ev["asn"] = C.asn_lookup(ips[0]) if ips else None
        try:
            ev["internetdb"] = C.internetdb(ips[0]) if ips else None
        except Exception:  # noqa: BLE001
            ev["internetdb"] = None
        if deep:
            for k, fn in (("crtsh", C.crtsh_lookup), ("wayback", C.wayback_first_seen)):
                try:
                    ev[k] = fn(reg)
                except Exception as e:  # noqa: BLE001
                    ev[k] = {"status": f"unavailable ({type(e).__name__})"}
        ev["seconds"] = round(time.time() - t0, 2)
        return ev

    # ------------------------------------------------------------------ the feature row the rules look at
    def row(self, t, ev):
        reg = t["reg"]
        row = F.lexical_frame([reg], self.brands).iloc[0].to_dict()
        row["shared_platform"] = int(t["shared_platform"])
        sub = t["subdomain"]
        lab = row["label"]
        row["brand_in_subdomain"] = int(bool(sub) and any(b in sub and b != lab for b in self.brands))
        row.update(F.network_frame([reg]).iloc[0].to_dict())
        ips = ev["dns"].get("ips", [])
        ip_hits, ns_hits = campaign.match(reg, ips, ev["dns"].get("ns", []))
        row["shared_ip_known_phish"], row["shared_ns_known_phish"] = len(ip_hits), len(ns_hits)
        row["_ip_hits"], row["_ns_hits"] = ip_hits, ns_hits
        ct = ev.get("crtsh") or {}
        if ct.get("first_cert"):
            try:
                d = datetime.fromisoformat(ct["first_cert"]).replace(tzinfo=timezone.utc)
                row["first_cert_age_days"] = (datetime.now(timezone.utc) - d).days
            except ValueError:
                pass
        wb = ev.get("wayback") or {}
        if wb.get("status") == "ok":
            row["wayback_archived"] = bool(wb.get("archived"))
        # URL path words (only when a full URL was given)
        pw = [w for w in PATH_WORDS if w in t["path"].lower()]
        row["path_words"] = pw
        return row

    # ------------------------------------------------------------------ main entry
    def investigate(self, text, deep=False):
        t0 = time.time()
        t = parse_target(text)
        ev = self.collect(t["reg"], deep=deep)
        return self._assemble(t, ev, t0)

    def _assemble(self, t, ev, t0):
        row = self.row(t, ev)
        score, fired, level = R.evaluate(row)
        extra = []
        if len(row["path_words"]) >= 2:
            extra.append(("U1", "Credential words in the URL path", "path contains: " + ", ".join(row["path_words"]), 10))
            score = min(100, score + 10)
            level = next(n for cut, n in R.LEVELS if score >= cut)
        fired = list(fired) + extra
        notes = []
        a = ev["dns"].get("a_status")
        if a == "nxdomain":
            notes.append("The name does not resolve (NXDOMAIN). It may never have worked or may already have been taken down.")
        elif a not in ("ok",):
            notes.append("DNS lookup was inconclusive; only name-based rules could be applied.")
        if ev["rdap"].get("status") in ("not_found",):
            notes.append("The registry has no record of this name (not registered or already deleted).")
        elif ev["rdap"].get("status") in ("no_rdap_for_tld",):
            notes.append("This top-level domain's registry does not offer RDAP, so age and registrar rules could not be applied.")
        if t["shared_platform"]:
            notes.append("Hosted on a shared platform: registration age and registrar describe the platform, not the site owner.")
        report = {"target": t, "risk_level": level, "score": int(score), "fired_rules": [dict(id=i, title=ti, reason=re_, points=p) for i, ti, re_, p in fired],
                  "notes": notes, "evidence": ev, "campaign": {"same_ip_known_phishing": [n.replace(".", "[.]") for n in row["_ip_hits"][:8]],
                                                              "same_ns_set_known_phishing": [n.replace(".", "[.]") for n in row["_ns_hits"][:8]]},
                  "age_days": None if row.get("age_days", -1) == -1 else round(row["age_days"]), "seconds": round(time.time() - t0, 2),
                  "caveat": "Passive screening only: the page was never opened. A LOW score does not prove a site is safe; on unseen feeds the rules catch only part of all phishing names."}
        if self.ml:
            report["ml_second_opinion"] = self._ml(t, row)
        return report

    def _ml(self, t, row):
        import numpy as np  # noqa: F401
        lex = self.ml["lex"]
        X = pd.DataFrame([row])
        out = {"lexical_score": round(float(lex["model"].predict_proba(X[lex["cols"]])[:, 1][0]), 3), "lexical_threshold": round(lex["threshold"], 3)}
        enr = self.ml["enr"]
        try:
            cols = enr["num"] + enr["cat"]
            out["enriched_score"] = round(float(enr["model"].predict_proba(X[cols])[:, 1][0]), 3)
            out["enriched_threshold"] = round(enr["threshold"], 3)
        except Exception:  # noqa: BLE001
            pass
        out["note"] = "statistical second opinion only; it does not change the rule verdict"
        return out


    # ------------------------------------------------------------------ streaming version for the web page
    def investigate_stream(self, text, deep=False):
        """yields (event, data) tuples: parsed, step_start, step_done, rule, done"""
        t0 = time.time()
        t = parse_target(text)
        reg = t["reg"]
        yield "parsed", t
        ev = {}

        def run(sid, label, fn, summarize):
            yield "step_start", {"id": sid, "label": label}
            ts = time.time()
            try:
                val = fn()
            except Exception as e:  # noqa: BLE001
                val = {"status": f"unavailable ({type(e).__name__})"}
            ev[sid] = val
            yield "step_done", {"id": sid, "label": label, "ms": int((time.time() - ts) * 1000), "summary": summarize(val)}

        yield from run("dns", "DNS records (A, NS, MX, TXT)", lambda: C.dns_lookup(reg),
                       lambda v: f"{v.get('a_status')}; {len(v.get('ips', []))} IP(s); {len(v.get('ns', []))} name server(s); MX {v.get('mx_count', 0)}")
        ips = ev["dns"].get("ips", [])
        yield from run("asn", "Hosting network (Team Cymru ASN)", lambda: C.asn_lookup(ips[0]) if ips else None,
                       lambda v: f"AS{v.get('asn')} {v.get('as_name', '')[:40]} ({v.get('cc')})" if v and v.get("asn") else "no IP to map")
        yield from run("rdap", "Registry data (RDAP)", lambda: C.rdap_lookup(reg),
                       lambda v: (f"registered {str(v.get('registered') or '-')[:10]}; registrar {v.get('registrar') or '-'}" if v.get("status") == "ok" else f"status: {v.get('status')}"))
        yield from run("dnsx", "Mail / www / CAA records", lambda: C.dns_extras(reg),
                       lambda v: f"DMARC {'yes' if v.get('has_dmarc') else 'no'}; www {'yes' if v.get('has_www') else 'no'}; CAA {'yes' if v.get('has_caa') else 'no'}")
        yield from run("internetdb", "Shodan InternetDB (server IP)", lambda: C.internetdb(ips[0]) if ips else None,
                       lambda v: f"ports {v.get('ports', [])}; vulnerabilities {len(v.get('vulns', []))}" if v else "no IP to look up")
        if deep:
            yield from run("crtsh", "Certificate-transparency logs (crt.sh)", lambda: C.crtsh_lookup(reg),
                           lambda v: f"{v.get('cert_count', '-')} certificates; first {v.get('first_cert', '-')}" if v.get("status") == "ok" else str(v.get("status")))
            yield from run("wayback", "Internet Archive history", lambda: C.wayback_first_seen(reg),
                           lambda v: f"archived: {v.get('archived')}" if v.get("status") == "ok" else str(v.get("status")))
        ev["seconds"] = round(time.time() - t0, 2)
        report = self._assemble(t, ev, t0)
        for f in report["fired_rules"]:
            yield "rule", f
        yield "done", report
