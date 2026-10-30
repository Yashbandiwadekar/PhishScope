"""Second enrichment pass: DNS extras (DMARC / www / CAA) and Shodan InternetDB for the first IP of every resolving name."""
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

import collectors as C

PROC = Path(__file__).resolve().parents[1] / "data" / "processed"


def one(name):
    try:
        d = C.cache_get("dns", name)
        if not d or d.get("a_status") != "ok":
            return False
        C.dns_extras(name)
        for ip in d.get("ips", [])[:1]:
            try:
                C.internetdb(ip)
            except Exception:  # noqa: BLE001 - InternetDB is best-effort
                pass
        return True
    except Exception as e:  # noqa: BLE001
        print("  error", name, type(e).__name__)
        return False


if __name__ == "__main__":
    files = [a for a in sys.argv[1:] if not a.startswith("--")] or ["subset_enrich", "test_crossfeed", "test_urlhaus_malware"]
    names = list(dict.fromkeys(sum([pd.read_csv(PROC / f"{f}.csv")["reg"].tolist() for f in files], [])))
    print(len(names), "names", flush=True)
    t0 = time.time()
    with ThreadPoolExecutor(10) as ex:
        for i, ok in enumerate(ex.map(one, names), 1):
            if i % 200 == 0:
                print(f"  {i}/{len(names)} {i / (time.time() - t0):.1f}/s", flush=True)
    print(f"done in {(time.time() - t0) / 60:.1f} min", flush=True)
