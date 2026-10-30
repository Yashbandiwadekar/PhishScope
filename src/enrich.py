"""Run the passive collectors over the registered names listed in the processed CSVs and fill the SQLite cache.

usage: python enrich.py [subset_enrich test_crossfeed test_urlhaus_malware] [--workers 12]
Progress is printed every 100 names; the script is resumable (cached names are skipped instantly).
"""
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

import collectors as C

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"


DNS_ONLY = False


def one(name):
    try:
        d = C.dns_lookup(name)
        for ip in d.get("ips", [])[:1]:
            C.asn_lookup(ip)
        if not DNS_ONLY:
            C.rdap_lookup(name)
        return True
    except Exception as e:  # noqa: BLE001
        print("  error", name, type(e).__name__, str(e)[:80])
        return False


def main():
    global DNS_ONLY
    argv = sys.argv[1:]
    if "--dns-only" in argv:
        DNS_ONLY = True
    workers = 12
    if "--workers" in argv:
        i = argv.index("--workers")
        workers = int(argv[i + 1])
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    files = args or ["subset_enrich", "test_crossfeed", "test_urlhaus_malware"]
    names = []
    for f in files:
        names += pd.read_csv(PROC / f"{f}.csv")["reg"].tolist()
    names = list(dict.fromkeys(names))
    print(f"{len(names)} registered names to enrich with {workers} workers", flush=True)
    t0 = time.time()
    done = 0
    C._rdap_bases()                                      # load bootstrap once, before threads start
    with ThreadPoolExecutor(workers) as ex:
        for ok in ex.map(one, names):
            done += 1
            if done % 100 == 0:
                rate = done / (time.time() - t0)
                print(f"  {done}/{len(names)}  {rate:.1f} names/s  eta {(len(names) - done) / max(rate, 0.01) / 60:.1f} min", flush=True)
    print(f"finished in {(time.time() - t0) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
