"""PhishScope command-line interface.

  python phishscope.py investigate <url-or-domain> [--deep] [--ml] [--json] [--html report.html]
  python phishscope.py rules                          list every detection rule with its points
  python phishscope.py monitor [--interval 300 --max-minutes 60]
  python phishscope.py web                            start the local web page (http://127.0.0.1:5000)

Passive only: the target is never contacted.
"""
import argparse
import json
import sys

import rules_engine as R

LEVEL_BAR = {"LOW": "[#.........]", "MEDIUM": "[#####.....]", "HIGH": "[##########]"}


def defang(s):
    return s.replace(".", "[.]")


def print_report(rep):
    t, ev = rep["target"], rep["evidence"]
    line = "=" * 78
    print(line)
    print(f" PhishScope report   target: {defang(t['host'])}   (registered name: {defang(t['reg'])})")
    print(line)
    print(f" VERDICT : {rep['risk_level']:<7}{LEVEL_BAR[rep['risk_level']]}   score {rep['score']}/100   ({rep['seconds']} s)")
    print(" scale   : LOW < 25 <= MEDIUM < 50 <= HIGH")
    print("\n WHY (rules that fired)")
    if rep["fired_rules"]:
        for f in rep["fired_rules"]:
            print(f"   +{f['points']:>2}  {f['id']:<3} {f['title']}")
            print(f"        {f['reason']}")
    else:
        print("   none - no rule fired")
    d, rd, asn, db = ev["dns"], ev["rdap"], ev.get("asn") or {}, ev.get("internetdb") or {}
    print("\n EVIDENCE (passive)")
    print(f"   DNS       : {d.get('a_status')}  IPs {', '.join(d.get('ips', [])[:3]) or '-'}  NS {', '.join(d.get('ns', [])[:2]) or '-'}  MX {d.get('mx_count', 0)}")
    print(f"   Hosting   : AS{asn.get('asn', '-')} {asn.get('as_name', '')[:40]} ({asn.get('cc', '-')})")
    print(f"   Registry  : {rd.get('status')}  registered {str(rd.get('registered') or '-')[:10]}  age {rep['age_days'] if rep['age_days'] is not None else '-'} days  registrar {rd.get('registrar') or '-'}")
    print(f"   Shodan IP : ports {db.get('ports', '-')}  vulns {len(db.get('vulns', [])) if db else '-'}")
    if "crtsh" in ev:
        c = ev["crtsh"]
        print(f"   Cert logs : {c.get('status')}  certificates {c.get('cert_count', '-')}  first {c.get('first_cert', '-')}")
    if "wayback" in ev:
        w = ev["wayback"]
        print(f"   Archive   : {w.get('status')}  archived {w.get('archived', '-')}")
    cm = rep["campaign"]
    if cm["same_ip_known_phishing"] or cm["same_ns_set_known_phishing"]:
        print("\n CAMPAIGN LINK")
        if cm["same_ip_known_phishing"]:
            print("   same IP as known phishing names :", ", ".join(cm["same_ip_known_phishing"][:5]))
        if cm["same_ns_set_known_phishing"]:
            print("   same name-server set            :", ", ".join(cm["same_ns_set_known_phishing"][:5]))
    for n in rep["notes"]:
        print(f"\n NOTE: {n}")
    if "ml_second_opinion" in rep:
        m = rep["ml_second_opinion"]
        print(f"\n ML second opinion: lexical {m.get('lexical_score')} (flag at >= {m.get('lexical_threshold')}), enriched {m.get('enriched_score', '-')} (flag at >= {m.get('enriched_threshold', '-')})")
    print("\n " + rep["caveat"])
    print(line)


def main():
    ap = argparse.ArgumentParser(prog="phishscope")
    sub = ap.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("investigate")
    inv.add_argument("target")
    inv.add_argument("--deep", action="store_true", help="also query certificate-transparency logs and the Internet Archive (slow)")
    inv.add_argument("--ml", action="store_true", help="add the machine-learning second opinion")
    inv.add_argument("--json", action="store_true")
    inv.add_argument("--html")
    sub.add_parser("rules")
    mon = sub.add_parser("monitor")
    mon.add_argument("--interval", type=int, default=300)
    mon.add_argument("--max-minutes", type=int, default=60)
    sub.add_parser("web")
    a, rest = ap.parse_known_args()

    if a.cmd == "rules":
        print(f"{'ID':<4}{'GROUP':<10}{'POINTS':>6}  TITLE  -  REASON")
        for r in R.RULES:
            print(f"{r.id:<4}{r.group:<10}{r.points:>6}  {r.title}  -  {r.reason}")
        print("\nLevels: LOW < 25 <= MEDIUM < 50 <= HIGH (score = sum of points, capped at 100)")
        return
    if a.cmd == "monitor":
        sys.argv = ["monitor.py", "--interval", str(a.interval), "--max-minutes", str(a.max_minutes)]
        import monitor
        monitor.main()
        return
    if a.cmd == "web":
        import webapp
        webapp.app.run(host="127.0.0.1", port=5000, debug=False)
        return
    import engine as E
    try:
        rep = E.Engine(with_ml=a.ml).investigate(a.target, deep=a.deep)
    except ValueError as e:
        print("error:", e)
        sys.exit(2)
    if a.json:
        print(json.dumps(rep, indent=2, default=str))
    else:
        print_report(rep)
    if a.html:
        import webapp
        open(a.html, "w", encoding="utf-8").write(webapp.render_report(rep))
        print("HTML report written to", a.html)


if __name__ == "__main__":
    main()
