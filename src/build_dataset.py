"""Build the frozen, de-biased dataset used by PhishScope.

Design choices (each guards against a known way of fooling yourself with this kind of data):
  * Negatives come from DEEP Tranco ranks (100,001-1,000,000), never the top sites, and rank is never used as a feature.
  * Everything is split by REGISTRABLE domain (eTLD+1, public-suffix-list private section included), so one base domain
    never lands in both train and test.
  * Entries on shared platforms (e.g. *.pages.dev, *.weebly.com) are flagged: the registration data of those names belongs
    to the platform, not the attacker.
  * A per-registrable-domain cap stops a few free hosts with thousands of subdomains from dominating the positives.
  * The cross-feed test set (OpenPhish positives + held-out Tranco negatives) is built here too and never used for training.

Output: data/processed/*.csv + dataset_summary.json (all random choices seeded).
"""
import csv
import io
import json
import re
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import tldextract
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
RAW = sorted((ROOT / "data" / "raw").glob("20*"))[-1]
OUT = ROOT / "data" / "processed"
OUT.mkdir(parents=True, exist_ok=True)
SEED = 42
N_PER_CLASS = 50_000          # large lexical corpus
CAP_PER_REG = 15              # max phishing entries kept per registrable domain
N_ENRICH_EACH = 1_200         # network-enriched subset (per class)
HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

EXTRACT = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=())  # offline snapshot shipped with the package


def split_host(h):
    e = EXTRACT(h)
    reg = f"{e.domain}.{e.suffix}" if e.suffix else e.domain
    return reg, e.suffix, e.subdomain, bool(e.is_private)


def clean_hosts(lines):
    seen, out = set(), []
    for ln in lines:
        h = ln.strip().lower().rstrip(".")
        if not h or h.startswith("#") or IP_RE.match(h) or not HOST_RE.match(h) or h in seen:
            continue
        seen.add(h)
        out.append(h)
    return out


def frame(hosts, label, source):
    rows = []
    for h in hosts:
        reg, suffix, sub, private = split_host(h)
        rows.append((h, reg, suffix, sub, int(private), label, source))
    return pd.DataFrame(rows, columns=["host", "reg", "suffix", "subdomain", "shared_platform", "label", "source"])


def main():
    rng = np.random.default_rng(SEED)
    summary = {"snapshot": RAW.name, "seed": SEED,
               "unit_of_analysis": "registrable name (eTLD+1, PSL private section included) for BOTH classes"}

    # --- positives: Phishing.Database, reduced to the registered name -------------------------------------------------
    phish_all = clean_hosts((RAW / "phishdb_domains.txt").read_text(errors="ignore").splitlines())
    summary["phishdb_clean_entries"] = len(phish_all)
    pdf = frame(phish_all, 1, "phishing_database")
    summary["phishdb_share_on_shared_platform"] = round(float(pdf.shared_platform.mean()), 4)
    summary["phishdb_share_with_subdomain"] = round(float((pdf.subdomain != "").mean()), 4)
    own = pdf[pdf.shared_platform == 0].sample(frac=1.0, random_state=SEED)       # shuffled, so de-dup keeps a random host
    summary["phishdb_own_registered_entries"] = len(own)
    own = own.drop_duplicates("reg")
    summary["phishdb_own_registered_unique_names"] = len(own)
    shared = pdf[pdf.shared_platform == 1].sample(frac=1.0, random_state=SEED).drop_duplicates("reg")
    summary["phishdb_shared_platform_unique_names"] = len(shared)

    # --- negatives: Tranco, deep ranks only (Tranco itself lists registered names, so the unit matches) -------------------
    with zipfile.ZipFile(RAW / "tranco_top1m.csv.zip") as z:
        tr = pd.read_csv(io.TextIOWrapper(z.open(z.namelist()[0]), encoding="utf-8"), names=["rank", "host"], header=None)
    tr["host"] = tr["host"].str.lower().str.strip()
    deep = tr[tr["rank"] > 100_000]
    deep = deep[deep.host.map(lambda h: bool(HOST_RE.match(h)) and not IP_RE.match(h))].sample(frac=1.0, random_state=SEED)
    ndf = frame(deep.host.tolist(), 0, "tranco_100k_1m")
    ndf = ndf[ndf.shared_platform == 0].drop_duplicates("reg")
    ndf = ndf[~ndf.reg.isin(set(pdf.reg))]                                         # name never appears on both sides
    ndf = ndf[~ndf.host.isin(set(phish_all))]
    summary["tranco_deep_own_registered_candidates"] = len(ndf)

    # --- balanced training corpus ---------------------------------------------------------------------------------------
    n = min(N_PER_CLASS, len(own), len(ndf) // 2)
    pos = own.sample(n=n, random_state=SEED)
    neg_train = ndf.iloc[:n]
    neg_xfeed = ndf.iloc[n:n + 1500]
    corpus = pd.concat([pos, neg_train], ignore_index=True).sample(frac=1.0, random_state=SEED)
    corpus.to_csv(OUT / "corpus_lexical.csv", index=False)
    summary["corpus_rows"] = len(corpus)
    summary["corpus_share_with_subdomain_pos_vs_neg"] = [round(float((pos.subdomain != "").mean()), 4), round(float((neg_train.subdomain != "").mean()), 4)]

    # --- enriched subset (registration + DNS lookups are slow, so a smaller subset) ----------------------------------------
    k = min(N_ENRICH_EACH, len(pos), len(neg_train))
    enrich = pd.concat([pos.sample(n=k, random_state=SEED), neg_train.sample(n=k, random_state=SEED)], ignore_index=True)
    enrich.to_csv(OUT / "subset_enrich.csv", index=False)
    summary["enrich_rows"] = len(enrich)

    # --- shared-platform phishing: evaluated for recall only (no fair benign counterpart in Tranco) -------------------------
    shared.sample(n=min(3000, len(shared)), random_state=SEED).to_csv(OUT / "test_sharedplatform_phish.csv", index=False)

    # --- cross-feed test: OpenPhish positives + held-out negatives ------------------------------------------------------------
    urls = [ln.strip() for ln in (RAW / "openphish_feed.txt").read_text(errors="ignore").splitlines() if ln.strip().startswith("http")]
    op = frame(clean_hosts([urlsplit(u).hostname or "" for u in urls]), 1, "openphish")
    summary["openphish_hosts"] = len(op)
    op = op[(op.shared_platform == 0)].drop_duplicates("reg")
    op = op[~op.reg.isin(set(pos.reg))]                                            # not in the training positives
    summary["openphish_own_registered_not_in_training"] = len(op)
    pd.concat([op, neg_xfeed], ignore_index=True).to_csv(OUT / "test_crossfeed.csv", index=False)
    summary["crossfeed_negatives"] = len(neg_xfeed)

    # --- out-of-distribution: malware hosts from URLhaus (not phishing) --------------------------------------------------------
    rows = []
    with (RAW / "urlhaus_recent.csv").open(encoding="utf-8", errors="ignore") as f:
        for r in csv.reader(l for l in f if not l.startswith("#")):
            if len(r) > 2 and r[2].startswith("http"):
                rows.append(urlsplit(r[2]).hostname or "")
    uh = frame(clean_hosts(rows), 1, "urlhaus_malware")
    uh = uh[(uh.shared_platform == 0) & ~uh.reg.isin(set(pos.reg))].drop_duplicates("reg").head(1500)
    uh.to_csv(OUT / "test_urlhaus_malware.csv", index=False)
    summary["urlhaus_names_kept"] = len(uh)

    summary["top_suffix_phish"] = Counter(pos.suffix).most_common(10)
    summary["top_suffix_benign"] = Counter(neg_train.suffix).most_common(10)
    summary["top_shared_platforms_in_phishing"] = Counter(shared.suffix).most_common(8)
    (OUT / "dataset_summary.json").write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
