# PhishScope

**An Open-Source-Intelligence-Driven Framework for Live Screening of Scam and Phishing Domains**
(BE mini project - OSINT)

PhishScope looks at a URL or domain **without ever opening it**. It collects public records about the name
(DNS, registry data via RDAP, hosting network, Shodan InternetDB, optionally certificate-transparency logs and the
Internet Archive), runs a transparent set of weighted rules, and returns a score, a risk level (LOW / MEDIUM / HIGH)
and the plain-English reasons. A second part links names that share infrastructure into candidate campaigns, and a
live monitor polls public phishing feeds and scores each newly listed name within seconds of seeing it.

> Passive only. No component sends a request to the domain being investigated, no credentials are used and phishing
> names are shown defanged (`example[.]com`) by default.

## Quick start (Windows, Python 3.12+)

```
pip install pandas numpy scikit-learn networkx tldextract requests matplotlib dnspython flask rapidfuzz joblib
cd "Mini Project\src"
python phishscope.py rules                                 # list the 21 rules and their points
python phishscope.py investigate nvidia.com                # command-line report
python phishscope.py investigate "hxxps://secure-login[.]example[.]top/verify" --deep
python phishscope.py web                                   # web interface at http://127.0.0.1:5000
python phishscope.py monitor --interval 600 --max-minutes 60
python -m unittest discover -s ..\tests -v                 # 16 unit tests
```

## What is in the web interface

| Tab | What you can do |
|---|---|
| Investigate | Submit a name; watch the passive lookups finish one by one, the rules drop in and the gauge settle |
| Live monitor | Auto-refreshing feed dashboard; filter, search, click a name to investigate it |
| Campaign graph | Drag/zoom a graph of names that share an IP or name-server set; pick a cluster |
| Evaluation | Charts of every measured result, plus a base-rate slider |
| Rules lab | Change the points of each rule and watch detection and false alarms change (exploration only) |
| How it works | Clickable component diagram |

## Folder layout

```
src/            collectors.py (passive sources + SQLite cache)   rules_engine.py (21 rules)   engine.py (investigation)
                features.py   campaign.py / graph_corr.py         monitor.py   phishscope.py (CLI)   webapp.py (Flask API)
                build_dataset.py  enrich*.py                      evaluate_rules.py  eval_fresh.py  train_*.py (ML comparison)
webapp/         single-page interface (index.html, app.css, app.js) - plain JavaScript, no libraries, works offline
data/raw/       dated snapshot of the downloaded feeds + manifest with SHA-256 hashes
data/processed/ frozen datasets, SQLite evidence cache (cache.db)
outputs/        results_*.json, figures, monitor.db, logs
tests/          unit tests
docs/           how-it-works note for the viva
report/         the mini project report
```

## Data sources and terms

| Source | Use | Terms |
|---|---|---|
| Phishing.Database | phishing names (training/evaluation) | MIT licence |
| OpenPhish community feed | unseen-feed test, live monitor | academic/research use permitted by its terms; raw data kept local |
| PhishStats API | fresh listings with timestamps, live monitor | free for research; anonymous cap 50 requests/day |
| Tranco list (list ID 56WKN) | benign reference names | research ranking; cite Le Pochat et al., NDSS 2019 |
| URLhaus (abuse.ch) | out-of-distribution malware hosts | abuse.ch fair-use principles |
| RDAP / IANA bootstrap, Team Cymru ASN DNS, Shodan InternetDB, crt.sh, Internet Archive | per-name evidence | public, free, non-commercial use |

## Honest limitations

* Passive evidence only: a clean result does not prove a site is safe.
* The phishing feed snapshot was stale: about three quarters of its names had already been taken down, so the
  evaluation is split into live names, an unseen feed and fresh listings. Names deleted from the registry after takedown
  are excluded to avoid a temporal leak.
* The rule weights are hand-set before evaluation and not tuned on test data; a data-learned weighting is reported only
  as a comparison. The rule engine is explainable but weaker than a trained model on the old snapshot.
* The unseen-feed test has only 62 live positives, so its confidence intervals are wide.
* Shared-platform names (free hosting) have no meaningful registration age.
