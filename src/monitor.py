"""Near-real-time monitor: poll public phishing feeds, score every NEW name within seconds of listing, log latency.

Sources polled (feed hosts only - a listed domain is never contacted over HTTP):
  * PhishStats API (latest 100 listings, with listing timestamps; free, anonymous cap 50 requests/day/IP)
  * OpenPhish community feed        (https://openphish.com/feed.txt)
  * Phishing.Database 'new in the last hour' list
State is kept in outputs/monitor.db so the run is resumable and de-duplicated.

Classification of each scored name:
  fresh     listed (per the feed's own timestamp) at most FRESH_HOURS before we scored it, or first seen in a LATER poll
  baseline  already listed for longer / first poll of a feed without timestamps

usage: python monitor.py --interval 600 --max-minutes 90
"""
import argparse
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

import engine as E

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "outputs" / "monitor.db"
UA = {"User-Agent": "PhishScope-student-miniproject/1.0 (academic research; passive lookups only)"}
FRESH_HOURS = 3
TEXT_FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "phishdb_new_last_hour": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-last-hour.txt",
}
PHISHSTATS = "https://api.phishstats.info/api/phishing?_sort=-date&_size=100"


def db():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.execute("""CREATE TABLE IF NOT EXISTS seen (host TEXT PRIMARY KEY, source TEXT, first_seen_utc TEXT, reg TEXT, score INTEGER, level TEXT,
                 rules TEXT, resolves INTEGER, age_days REAL, latency_s REAL, shared_platform INTEGER, notes TEXT)""")
    cols = {r[1] for r in c.execute("PRAGMA table_info(seen)")}
    for name, typ in (("listed_utc", "TEXT"), ("delay_s", "REAL")):
        if name not in cols:
            c.execute(f"ALTER TABLE seen ADD COLUMN {name} {typ}")
    c.commit()
    return c


def host_of(line):
    h = (urlsplit(line).hostname if line.startswith("http") else line).lower() if line else None
    return h if h and E.HOST_RE.match(h) and not E.IP_RE.match(h) else None


def poll_text(url):
    try:
        r = requests.get(url, headers=UA, timeout=45)
        if r.status_code != 200 or b"<html" in r.content[:200].lower():
            return []
        return [(host_of(ln.strip()), ln.strip()) for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#") and host_of(ln.strip())]
    except requests.RequestException:
        return []


def poll_phishstats():
    try:
        r = requests.get(PHISHSTATS, headers=UA, timeout=45)
        if r.status_code != 200:
            print(f"  phishstats HTTP {r.status_code}", flush=True)
            return []
        out = []
        for e in r.json():
            h = host_of(e.get("url", ""))
            if h:
                out.append((h, e["url"], e.get("date")))
        return out
    except (requests.RequestException, ValueError):
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=600)
    ap.add_argument("--max-minutes", type=int, default=90)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    eng = E.Engine()
    con = db()
    t_end = time.time() + a.max_minutes * 60
    n_poll = 0
    while time.time() < t_end:
        n_poll += 1
        known = {r[0] for r in con.execute("SELECT host FROM seen")}
        now = datetime.now(timezone.utc)
        batch = {}
        for src, url in TEXT_FEEDS.items():
            items = poll_text(url)
            tag = src + ("_baseline" if n_poll == 1 and not any(r[0] for r in con.execute("SELECT 1 FROM seen WHERE source LIKE ? LIMIT 1", (src + "%",))) else "")
            fresh = [(h, ln, tag, None) for h, ln in items if h not in known]
            print(f"{now:%H:%M:%S}Z poll {src}: {len(items)} entries, {len(fresh)} new", flush=True)
            for h, ln, t_, l in fresh:
                batch.setdefault(h, (h, ln, t_, l))
        ps = poll_phishstats()
        new_ps = 0
        for h, ln, listed in ps:
            if h in known or h in batch:
                continue
            try:
                age_h = (now - datetime.fromisoformat(listed.replace("Z", "+00:00"))).total_seconds() / 3600
            except (ValueError, AttributeError):
                age_h = 99
            batch[h] = (h, ln, "phishstats" if age_h <= FRESH_HOURS or n_poll > 1 else "phishstats_baseline", listed)
            new_ps += 1
        print(f"{now:%H:%M:%S}Z poll phishstats: {len(ps)} entries, {new_ps} new", flush=True)
        stamp = now.isoformat(timespec="seconds")

        def work(item):
            h, ln, src, listed = item
            t0 = time.time()
            try:
                rep = eng.investigate(ln if ln.startswith("http") else h)
            except Exception as e:  # noqa: BLE001
                return (h, src, stamp, None, None, None, "", None, None, time.time() - t0, 0, f"error {type(e).__name__}", listed, None)
            ev = rep["evidence"]
            delay = None
            if listed:
                try:
                    delay = (datetime.now(timezone.utc) - datetime.fromisoformat(listed.replace("Z", "+00:00"))).total_seconds()
                except ValueError:
                    pass
            return (h, src, stamp, rep["target"]["reg"], rep["score"], rep["risk_level"], ",".join(r["id"] for r in rep["fired_rules"]),
                    int(ev["dns"].get("a_status") == "ok"), rep["age_days"], time.time() - t0, int(rep["target"]["shared_platform"]), "; ".join(rep["notes"])[:200], listed, delay)

        with ThreadPoolExecutor(a.workers) as ex:
            for res in ex.map(work, list(batch.values())):
                con.execute("INSERT OR REPLACE INTO seen (host,source,first_seen_utc,reg,score,level,rules,resolves,age_days,latency_s,shared_platform,notes,listed_utc,delay_s) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", res)
                con.commit()
                if not a.quiet and res[5] in ("HIGH", "MEDIUM"):
                    print(f"  ALERT {res[5]:<6} score {res[4]:>3}  {res[0].replace('.', '[.]')}  rules {res[6]}  ({res[9]:.1f}s)", flush=True)
        n = con.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
        print(f"{datetime.now(timezone.utc):%H:%M:%S}Z total stored: {n}", flush=True)
        if time.time() + a.interval >= t_end:
            break
        time.sleep(a.interval)
    print("monitor finished", flush=True)


if __name__ == "__main__":
    main()
