"""Analyse what the live monitor collected: fresh listings (PhishStats, <=3 h old when scored) vs baseline listings.

Reports, per group: how many names, share that resolve, level distribution (with Wilson intervals), how often each rule fires, how old the
registrations are, and the time from LISTING to VERDICT (feed timestamp -> score) plus pure processing time per name.
Benign reference = the live Tranco names scored earlier (registration age taken from the same RDAP cache).
Writes outputs/results_fresh.json and outputs/fig_fresh.png
"""
import json
import re
import sqlite3
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import evalkit as K
import features as F

ROOT = Path(__file__).resolve().parents[1]
OUT, PROC = ROOT / "outputs", ROOT / "data" / "processed"


def levels(df):
    n = len(df)
    out = {"n": n}
    for lv in ("HIGH", "MEDIUM", "LOW"):
        k = int((df.level == lv).sum())
        out[lv] = {"n": k, "share": k / max(n, 1), "ci95": K.wilson(k, n)}
    k = int((df.level.isin(["HIGH", "MEDIUM"])).sum())
    out["MEDIUM_PLUS"] = {"n": k, "share": k / max(n, 1), "ci95": K.wilson(k, n)}
    return out


def main():
    con = sqlite3.connect(OUT / "monitor.db")
    df = pd.read_sql_query("SELECT * FROM seen WHERE level IS NOT NULL", con)
    df["group"] = df.source.map(lambda s: "fresh (PhishStats, <=3 h old)" if s == "phishstats" else "baseline (PhishStats, older)" if s == "phishstats_baseline"
                                else "baseline (OpenPhish feed)" if s.startswith("openphish") else s)
    res = {"total_scored": int(len(df)), "groups": {}}
    for g, d in df.groupby("group"):
        rules = d.rules.fillna("").map(lambda r: [x for x in r.split(",") if x])
        fire = {}
        for rid in sorted({x for r in rules for x in r}):
            fire[rid] = float(rules.map(lambda r, rid=rid: rid in r).mean())
        ages = d.age_days.dropna()
        info = {"levels": levels(d), "resolves_share": float(d.resolves.mean()), "rule_fire_rate": fire,
                "registered_age": {"n_with_age": int(len(ages)), "lt30d": float((ages < 30).mean()) if len(ages) else None, "lt90d": float((ages < 90).mean()) if len(ages) else None,
                                   "lt365d": float((ages < 365).mean()) if len(ages) else None, "median_days": float(ages.median()) if len(ages) else None},
                "processing_seconds": {"mean": float(d.latency_s.mean()), "median": float(d.latency_s.median()), "p95": float(d.latency_s.quantile(.95)), "max": float(d.latency_s.max())},
                "shared_platform_share": float(d.shared_platform.mean())}
        if d.delay_s.notna().any():
            dl = d.delay_s.dropna() / 60
            info["listing_to_verdict_minutes"] = {"n": int(len(dl)), "median": float(dl.median()), "p25": float(dl.quantile(.25)), "p75": float(dl.quantile(.75)), "min": float(dl.min()), "max": float(dl.max())}
        res["groups"][g] = info
    res["processing_seconds_all"] = {"n": int(len(df)), "mean": float(df.latency_s.mean()), "median": float(df.latency_s.median()), "p95": float(df.latency_s.quantile(.95)), "max": float(df.latency_s.max())}
    # benign reference: live Tranco names (same RDAP cache)
    sub = pd.read_csv(PROC / "subset_enrich.csv")
    ben = sub[sub.label == 0]
    net = F.network_frame(ben.reg.tolist())
    net = net[(net.dns_ok == 1) & (net.rdap_ok == 1)]
    a = net.age_days[net.age_days >= 0]
    res["benign_reference"] = {"n_with_age": int(len(a)), "lt30d": float((a < 30).mean()), "lt90d": float((a < 90).mean()), "lt365d": float((a < 365).mean()), "median_days": float(a.median())}
    # observation window, from the monitor logs: every poll of every feed and how many new names it gave
    polls = {}
    times = []
    for log in sorted(OUT.glob("monitor_log*.txt")):
        for ln in log.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"(\d\d:\d\d:\d\d)Z poll (\S+): (\d+) entries, (\d+) new", ln)
            if m:
                times.append(m.group(1))
                polls.setdefault(m.group(2), []).append(int(m.group(4)))
    if polls:
        res["observation"] = {"first_poll_utc": min(times), "last_poll_utc": max(times), "date_utc": str(pd.to_datetime(df.first_seen_utc).min().date()),
                              "feeds": {f: {"polls": len(v), "new_total": sum(v), "polls_with_new": sum(1 for x in v if x), "new_per_poll": v} for f, v in polls.items()}}
    rr = json.load(open(OUT / "results_rules.json"))
    res["benign_false_alarm_rates_live_tranco"] = {k: {"fpr": v["fpr"], "fpr_ci95": v["fpr_ci95"]} for k, v in rr["subset_live_names"]["levels"].items()}
    (OUT / "results_fresh.json").write_text(json.dumps(res, indent=2, default=float))

    # figure: delay histogram, level shares, registration age
    fig, ax = plt.subplots(1, 3, figsize=(13, 3.8))
    fr = df[df.group.str.startswith("fresh")]
    if len(fr) and fr.delay_s.notna().any():
        ax[0].hist(fr.delay_s.dropna() / 60, bins=14, color="#2f6fa5")
    ax[0].set_xlabel("minutes from listing to verdict")
    ax[0].set_ylabel("names")
    ax[0].set_title("Fresh listings: time to verdict")
    groups = list(res["groups"])
    x = np.arange(len(groups))
    bottom = np.zeros(len(groups))
    for lv, col in (("HIGH", "#c0392b"), ("MEDIUM", "#c98a12"), ("LOW", "#2e9a63")):
        v = np.array([res["groups"][g]["levels"][lv]["share"] for g in groups])
        ax[1].bar(x, v, bottom=bottom, color=col, label=lv)
        bottom += v
    ax[1].set_xticks(x)
    ax[1].set_xticklabels([g.replace(" (", "\n(") for g in groups], fontsize=7)
    ax[1].set_ylabel("share of names")
    ax[1].legend(fontsize=7)
    ax[1].set_title("Rule level of listed phishing names")
    bins = np.logspace(0, 4.3, 30)
    fa = fr.age_days.dropna() if len(fr) else pd.Series(dtype=float)
    fa = fa[fa >= 0]
    if len(fa):   # share of names per bin (density on log-spaced bins would exaggerate the narrow young bins)
        ax[2].hist(fa.clip(lower=1), bins=bins, alpha=.7, color="#c0392b", label=f"fresh phishing listings (n={len(fa)})", weights=np.full(len(fa), 1 / len(fa)))
    ax[2].hist(a.clip(lower=1), bins=bins, alpha=.5, color="#2e9a63", label=f"benign live, Tranco (n={len(a)})", weights=np.full(len(a), 1 / len(a)))
    ax[2].set_xscale("log")
    ax[2].set_ylabel("share of names")
    ax[2].set_xlabel("age of registration (days, log scale)")
    ax[2].legend(fontsize=7)
    ax[2].set_title("Registration age")
    fig.tight_layout()
    fig.savefig(OUT / "fig_fresh.png", dpi=170)
    plt.close(fig)
    print(json.dumps({g: {"n": v["levels"]["n"], "HIGH": round(v["levels"]["HIGH"]["share"], 3), "MEDIUM+": round(v["levels"]["MEDIUM_PLUS"]["share"], 3), "resolves": round(v["resolves_share"], 3),
                          "age<30d": v["registered_age"]["lt30d"], "delay_min_median": (v.get("listing_to_verdict_minutes") or {}).get("median")} for g, v in res["groups"].items()}, indent=1, default=float))
    print("benign age<30d:", round(res["benign_reference"]["lt30d"], 4), "| <365d:", round(res["benign_reference"]["lt365d"], 3))


if __name__ == "__main__":
    main()
