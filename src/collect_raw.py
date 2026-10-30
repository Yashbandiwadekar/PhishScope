"""Download the raw public datasets used by PhishScope into data/raw/<snapshot-date>/ and record a manifest.

Sources (all public, passive: only the feed hosts are contacted, never a listed phishing domain):
  * Phishing.Database  - phishing-domains-ACTIVE.txt           (MIT licence)
  * Tranco             - top-1m.csv.zip + list id for citation (research-oriented top-sites ranking)
  * URLhaus (abuse.ch) - csv_recent                            (free under abuse.ch fair-use principles)
  * OpenPhish          - community feed.txt                    (academic/research use permitted by its terms)

Usage:  python collect_raw.py
"""
import hashlib
import json
import sys
import time
from datetime import date
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
SNAP = ROOT / "data" / "raw" / date.today().isoformat()
UA = {"User-Agent": "OSINT-student-miniproject/1.0 (academic research; passive lookups only)"}

SOURCES = {
    "phishdb_domains.txt": ("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", "text"),
    "tranco_top1m.csv.zip": ("https://tranco-list.eu/top-1m.csv.zip", "zip"),
    "urlhaus_recent.csv": ("https://urlhaus.abuse.ch/downloads/csv_recent/", "text"),
    "openphish_feed.txt": ("https://openphish.com/feed.txt", "text"),
}


def fetch(name, url, kind, tries=4):
    for attempt in range(1, tries + 1):
        try:
            r = requests.get(url, headers=UA, timeout=90)
            body = r.content
            head = body[:200].lower()
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            if kind == "text" and (b"<html" in head or b"<!doctype" in head):
                raise RuntimeError("got an HTML page instead of the feed")
            if kind == "zip" and not body.startswith(b"PK"):
                raise RuntimeError("not a zip file")
            return body, r
        except Exception as e:  # noqa: BLE001 - report and retry
            print(f"  {name}: attempt {attempt} failed ({e})")
            time.sleep(4 * attempt)
    return None, None


def main():
    SNAP.mkdir(parents=True, exist_ok=True)
    manifest = {"snapshot_date": date.today().isoformat(), "collected_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": {}}
    for name, (url, kind) in SOURCES.items():
        body, r = fetch(name, url, kind)
        if body is None:
            manifest["files"][name] = {"url": url, "status": "FAILED"}
            print(f"{name}: FAILED")
            continue
        (SNAP / name).write_bytes(body)
        manifest["files"][name] = {"url": url, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "status": "ok"}
        print(f"{name}: {len(body):,} bytes")
    # Tranco list id (needed to cite the exact list used)
    try:
        j = requests.get("https://tranco-list.eu/api/lists/date/latest", headers=UA, timeout=30).json()
        manifest["tranco_list"] = {k: j.get(k) for k in ("list_id", "created_on", "available")}
        print("Tranco list:", manifest["tranco_list"])
    except Exception as e:  # noqa: BLE001
        print("could not read Tranco list id:", e)
    (SNAP / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print("manifest ->", SNAP / "manifest.json")
    return 0 if all(v.get("status") == "ok" for v in manifest["files"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
