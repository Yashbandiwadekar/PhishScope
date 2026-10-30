"""Build the mini project report (University of Mumbai layout) from the saved results.  python build_report.py"""
import importlib.metadata as md
import json
import sys
from pathlib import Path

from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Cm, Pt

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docx_helpers as H  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT, SHOT = ROOT / "outputs", ROOT / "screenshots"
J = lambda n: json.load(open(OUT / n, encoding="utf-8"))
R, M, L, GA, GS = J("results_rules.json"), J("results_enriched.json"), J("results_lexical.json"), J("graph_summary.json"), J("graph_summary_specific.json")
D = json.load(open(ROOT / "data" / "processed" / "dataset_summary.json"))
try:
    FR = J("results_fresh.json")
except Exception:  # noqa: BLE001
    FR = None

pct = lambda x, d=1: "-" if x is None else f"{100 * x:.{d}f}%"
f3 = lambda x: "-" if x is None else f"{x:.3f}"
f2 = lambda x: "-" if x is None else f"{x:.2f}"
ci = lambda c, d=0: f"[{100 * c[0]:.{d}f}-{100 * c[1]:.{d}f}%]"

STUDENT, SUPERVISOR, COORDINATOR, PRINCIPAL = "Yash Rajesh Bandiwadekar", "Prof. Pragati Pal", "Er. Samana Jafri", "Dr. Shafi Pathan"
TITLE = "PhishScope: An Open-Source-Intelligence-Driven Framework for Live Screening of Scam and Phishing Domains"
doc = H.new_document()
P = lambda t, **k: H.para(doc, t, **k)
B = lambda t: H.bullet(doc, t)
H1 = lambda t: H.heading(doc, t, 1)
H2 = lambda t: H.heading(doc, t, 2)
H3 = lambda t: H.heading(doc, t, 3)
CEN = WD_ALIGN_PARAGRAPH.CENTER

# ====================================================================== TITLE PAGE, CERTIFICATE, APPROVAL (college format)
def add_cover(doc):
    """Insert the three cover pages in the college's format: report/cover/cover_body.xml (paragraphs + page set-up of
    the section) and the college logo it shows. Paragraph defaults of the source were single spacing, no space after,
    left aligned, so those are made explicit here (this document's Normal style is 1.5-spaced and justified)."""
    import io
    from docx.oxml import parse_xml                                 # python-docx element classes (paragraph API works)
    from docx.oxml.ns import qn
    from docx.shared import Twips
    from docx.text.paragraph import Paragraph
    cov = ROOT / "report" / "cover"
    src = parse_xml((cov / "cover_body.xml").read_bytes())
    rid, _ = doc.part.get_or_add_image(io.BytesIO((cov / "college_logo.jpg").read_bytes()))
    W14, WP14 = "http://schemas.microsoft.com/office/word/2010/wordml", "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing"
    anchor, mar = doc.element.body.sectPr, None
    for el in list(src):
        if el.tag == qn("w:sectPr"):
            mar = el.find(qn("w:pgMar"))
            continue
        for e in el.iter():                                         # drop Word revision ids / w14 paragraph ids
            for att in list(e.attrib):
                if att.startswith("{%s}" % W14) or att.startswith("{%s}" % WP14) or att.startswith(qn("w:rsid")):
                    del e.attrib[att]
        for blip in el.iter("{http://schemas.openxmlformats.org/drawingml/2006/main}blip"):
            blip.set(qn("r:embed"), rid)
        anchor.addprevious(el)
        if el.tag == qn("w:p"):
            pf = Paragraph(el, doc._body)
            if pf.paragraph_format.space_after is None:
                pf.paragraph_format.space_after = Pt(0)
            if pf.paragraph_format.space_before is None:
                pf.paragraph_format.space_before = Pt(0)
            if pf.paragraph_format.line_spacing is None:
                pf.paragraph_format.line_spacing = 1.0
            if pf.alignment is None:
                pf.alignment = WD_ALIGN_PARAGRAPH.LEFT
    sec = doc.sections[0]
    for side in ("top", "bottom", "left", "right", "header", "footer"):
        setattr(sec, side + ("_distance" if side in ("header", "footer") else "_margin"), Twips(int(mar.get(qn("w:" + side)))))


add_cover(doc)

# ====================================================================== FRONT MATTER (roman numerals)
H.section_break(doc, "lowerRoman", 1)
P("Contents", size=15, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=14)
H.toc_field(doc, 'TOC \\o "1-3" \\h \\z \\u', "Right-click here and choose Update Field to build the table of contents.")
H.page_break(doc)
P("List of Figures", size=15, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=14)
H.toc_field(doc, 'TOC \\h \\z \\c "Figure"', "Right-click here and choose Update Field.")
H.page_break(doc)
P("List of Tables", size=15, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=14)
H.toc_field(doc, 'TOC \\h \\z \\c "Table"', "Right-click here and choose Update Field.")
H.page_break(doc)

fresh_txt = ""
if FR and "fresh (PhishStats, <=3 h old)" in FR["groups"]:
    g = FR["groups"]["fresh (PhishStats, <=3 h old)"]
    dl = g.get("listing_to_verdict_minutes") or {}
    only_first = FR.get("observation", {}).get("feeds", {}).get("phishstats", {}).get("polls_with_new") == 1
    fresh_txt = (f" On {g['levels']['n']} freshly listed names collected live, the rules raised MEDIUM or HIGH for {pct(g['levels']['MEDIUM_PLUS']['share'], 0)} "
                 f"(HIGH {pct(g['levels']['HIGH']['share'], 0)}); each verdict took a median of {g['processing_seconds']['median']:.1f} s of processing"
                 + ("." if only_first or not dl else f", and names were scored a median of {dl['median']:.0f} minutes after the feed listed them."))
H1("Abstract")
P(f"Phishing and scam websites appear in very large numbers and many disappear within days, so blocklists often list a site only after victims have been reached. This project presents PhishScope, a framework that judges a URL or domain before anyone opens it, using only public, passive information about the name: how it is spelt, when it was registered, which DNS and hosting network it uses, and whether the same infrastructure already hosts known phishing. PhishScope never contacts the site under investigation. Evidence is gathered from DNS, the registry (RDAP), Team Cymru's ASN service, Shodan InternetDB and, optionally, certificate-transparency logs and the Internet Archive; 21 transparent weighted rules turn it into a 0-100 score, a LOW/MEDIUM/HIGH level and plain-English reasons. A graph module links names that share an IP address or a rare name-server set into candidate campaigns, a monitor scores newly listed names within seconds, and a single-page web interface streams the analysis live.")
P(f"The evaluation was designed to avoid the shortcuts that make phishing detectors look better than they are. A naive set-up reaches near-perfect accuracy because benign ranking lists contain registered names while phishing feeds contain full host names, and about a third of the feed sits on free-hosting platforms; both classes were therefore compared at the registered-name level, and the feed snapshot, in which only {pct(M['dns_resolves_by_class']['phishing'], 0)} of sampled names still resolved, was handled explicitly. On an unseen feed (OpenPhish, live names) the rule engine reached ROC-AUC {f2(R['cross_feed_openphish_live']['roc_auc'])}; HIGH alerts caught {pct(R['cross_feed_openphish_live']['levels']['HIGH (score>=50)']['recall'])} of phishing names at {pct(R['cross_feed_openphish_live']['levels']['HIGH (score>=50)']['fpr'])} false alarms, and MEDIUM-or-higher caught {pct(R['cross_feed_openphish_live']['levels']['MEDIUM+ (score>=25)']['recall'])} at {pct(R['cross_feed_openphish_live']['levels']['MEDIUM+ (score>=25)']['fpr'])}. Machine-learning models trained for comparison were stronger on the old snapshot (AUC {f2(M['B_ablation_cv']['All features']['auc_mean'])} against {f2(R['subset_live_names']['roc_auc'])}) but less explainable. Linking names by shared IP and name-server set made phishing names {pct(GS['phishing_share_inside_clusters'], 0)} of clustered names against {pct(GS['baseline_phishing_share_in_sample'], 0)} in the sample.{fresh_txt} The report states the limitations plainly: passive evidence cannot prove a site safe, and the results are measured on public feeds of limited size.")
H.page_break(doc)
H1("Acknowledgments")
P(f"I would like to express my sincere thanks to my guide, {SUPERVISOR}, for guidance and encouragement throughout this project. I am grateful to {COORDINATOR}, Co-ordinator CSE (IOTCSBCT), and our Principal, {PRINCIPAL}, for their continuous support, and to the faculty of the department for the resources and references that made this work possible. I also thank the maintainers of the public data sources and open-source libraries used in the project, and my family and friends for their support.")
P(STUDENT, bold=True, align=WD_ALIGN_PARAGRAPH.RIGHT)

# ====================================================================== MAIN MATTER (arabic, restart at 1)
H.section_break(doc, "decimal", 1)
# ---------------------------------------------------------------- 1 INTRODUCTION
H1("1. Introduction")
H2("1.1 Background")
P("Phishing is the practice of luring a person to a counterfeit website, message or login page in order to steal credentials, money or personal data. Scam websites extend the idea to fake shops, fake investment platforms and fake support pages. The volume is large and still growing: the Anti-Phishing Working Group (APWG) counted 971,181 phishing attacks in the first quarter of 2026 [1], and in June 2026 alone it recorded 425,808 unique phishing websites, the highest monthly total since April 2023 [2].")
P("Defence against these sites is mostly reactive. Browser and email filters rely on blocklists, which can only list a site after somebody has reported or analysed it; research on malicious-URL detection has long pointed out that blocklists are never exhaustive and cannot cover newly created sites [3], [4]. Attackers exploit this gap by registering fresh domains in bulk and abandoning them quickly. A defender who can judge a link in the first minutes of its life, without visiting it, closes part of that gap.")
H2("1.2 Why open-source intelligence")
P("Open-source intelligence (OSINT) is information gathered from publicly available sources. A domain name leaves many public traces without anyone touching the website itself: DNS records, the registry's record of who registered it and when, the network that hosts it, certificates issued for it, and its history in web archives. These traces are the evidence PhishScope uses. Collecting them is passive: the investigator asks public services about the name and never connects to the suspected site, so it is safe to use on live phishing links and leaves no trace on the attacker's server.")
H2("1.3 Problem statement")
P("Given a URL or domain name, decide how likely it is to be a scam or phishing site using only passive public information, explain the decision in terms a non-specialist can follow, relate the name to known phishing infrastructure, and do so quickly enough to be useful for newly listed names.")
H2("1.4 Objectives")
for t in ("Identify and implement a set of passive OSINT collectors (DNS, registry, hosting network, server exposure, certificate and archive history) behind one cached interface.",
          "Design an explainable rule engine that turns the evidence into a score, a level and reasons.",
          "Build a bias-aware evaluation dataset and measure the engine honestly, including on a feed it was not developed on and on fresh listings.",
          "Link names that share infrastructure into candidate campaigns using graph community detection.",
          "Provide a command-line tool, a live monitor and an interactive web interface.",
          "Compare the rule engine with machine-learning models so that the benefit of explainability can be weighed against accuracy."):
    B(t)
H2("1.5 Scope and constraints")
P("The project is passive only. It does not open, crawl, screenshot or interact with any listed site; it does not analyse page content; it uses no accounts, API keys or credentials; and it processes only domain-level public records, not personal data. Only free public sources are used, and their terms of use were read before use (Section 3.3). The work is student-scale: datasets of tens of thousands of names and lookups limited by the polite rate of the free services.")
H2("1.6 Contributions")
for t in ("A reproducible, bias-aware dataset construction in which the unit of analysis is the registered name for both classes, shared-platform names are evaluated separately and names deleted after takedown are excluded (Section 4.2).",
          "A transparent rule engine of 21 weighted rules with reasons, whose weights were fixed before evaluation (Section 4.5).",
          "An infrastructure-correlation module with hub pruning and Louvain community detection (Section 4.6).",
          "A live monitor that records the time from listing to verdict (Section 4.8) and an interactive single-page interface (Section 4.9).",
          "An evaluation that reports negative as well as positive findings, with confidence intervals and a base-rate analysis (Chapter 5)."):
    B(t)
H2("1.7 Organisation of the report")
P("Chapter 2 surveys related work. Chapter 3 identifies the components of the system. Chapter 4 describes the design and implementation. Chapter 5 presents the evaluation. Chapter 6 concludes with advantages, disadvantages and future work. The appendices list the rules, the command-line reference and the reproduction steps.")

# ---------------------------------------------------------------- 2 LITERATURE SURVEY
H.page_break(doc)
H1("2. Literature Survey")
P("This chapter reviews the techniques that PhishScope builds on and the evaluation pitfalls it tries to avoid.")
H2("2.1 URL- and host-based detection")
P("Ma, Saul, Savage and Voelker showed that lexical features of a URL together with host-based features such as DNS and registration information can classify malicious sites without fetching the page, reporting accuracy of 95-99% on their data [3]. Sahoo, Liu and Hoi later surveyed the field and formalised malicious-URL detection as a machine-learning task, categorising work by feature representation and algorithm [4]. PhishScope follows the same passive philosophy but replaces the learned classifier by explicit rules so that every alert can be explained, and it keeps a learned model only as a comparison.")
H2("2.2 Registration-based and proactive detection")
P("Felegyhazi, Kreibich and Paxson used properties of domain registrations and their appearance in DNS zone files to infer new malicious domains from a few known-bad ones; they found that about 93% of the inferred domains later appeared suspect and that proactive blocking gave a median head start of about two days over a reactive blacklist [5]. Hao et al.'s PREDATOR system classifies domains at the time of registration, exploiting the fact that miscreants must register many domains, which leads to abnormal behaviour such as burst registrations and textually similar names [6]. These results motivate the registry-age and bulk-registration ideas in PhishScope's rules and graph module.")
H2("2.3 Typosquatting and brand impersonation")
P("Szurdi et al. studied typosquatting domain names and found that the problem extends deep into the long tail of the popularity distribution: only 6.8% of the typo domains they identified targeted the 10,000 most popular .com domains [7]. The edit distance introduced by Levenshtein [8] is the standard measure of how close two names are, and PhishScope uses it to compare a name with the most popular names in the Tranco ranking [12].")
H2("2.4 Infrastructure correlation")
P("Attackers reuse infrastructure, so names that share an IP address or name servers often belong to one campaign [5]. Community-detection methods can find such groups in a graph; PhishScope uses the Louvain method of Blondel et al. [9], which optimises modularity heuristically and scales to large graphs, implemented in NetworkX [18].")
H2("2.5 Evaluation pitfalls")
P("Arp et al. catalogue pitfalls of machine learning in security, including sampling bias, label inaccuracy and unrealistic evaluation settings, and show that they are common in published work [10]. Axelsson's base-rate fallacy explains why a detector with a low false-alarm rate can still produce mostly false alarms when the attack is rare: the false-alarm rate, not the detection rate, becomes the limiting factor [11]. Both ideas shaped the evaluation in Chapter 5: the dataset is de-biased, results are reported with confidence intervals and a base-rate analysis is included.")
H2("2.6 Public data and standards")
P("The Registration Data Access Protocol (RDAP) is the standardised, JSON-based replacement for WHOIS: RFC 9082 defines the query format [13], RFC 9083 the JSON responses [14] and RFC 9224 how to find the authoritative server for a name through the IANA bootstrap registry [15], [23]. Certificate Transparency (RFC 6962 [16], since superseded by RFC 9162) provides public logs of issued certificates. The Tranco list is a research-oriented ranking of popular sites designed to resist manipulation [12].")
H2("2.7 Summary and positioning")
H.table(doc, ["Approach", "Strength", "Limitation", "In PhishScope"],
        [["Blocklists", "very precise for known sites", "reactive; misses new sites [3], [4]", "used only as labelled data and live feeds"],
         ["URL/host classifiers [3], [4]", "work before the page is opened", "opaque; need labelled data and are easy to over-estimate [10]", "learned models kept as a comparison"],
         ["Registration-time reputation [5], [6]", "early; uses registry behaviour", "needs registry/zone access", "registry age and bulk-registration ideas as rules"],
         ["Typosquat analysis [7], [8]", "targets brand impersonation", "does not cover compromised sites", "edit-distance rule N1"],
         ["Infrastructure graphs [9]", "finds campaigns", "hosting providers link everything", "hub pruning; IP + name-server signals"]],
        [3.6, 3.4, 4.0, 4.0], caption_text="Related approaches and their relation to this work")
P("The gap this project addresses is a passive, explainable screener that is evaluated honestly on live data, with the dataset pitfalls made explicit, rather than another high-accuracy classifier.")

# ---------------------------------------------------------------- 3 IDENTIFICATION OF COMPONENTS
H.page_break(doc)
H1("3. Identification of Components")
H2("3.1 System overview")
P("PhishScope consists of four bands of components (architecture figure below): public data sources, which are only read; passive collection, which builds the datasets and gathers and caches evidence; analysis, which turns evidence into features, campaign links, rule results and a report; and outputs, which are the interfaces, the live monitor, the evaluation and the machine-learning comparison. Two long arrows leave the bands: the live monitor polls the phishing feeds directly, and the frozen test sets go from the dataset builder straight to the evaluation. The same diagram is clickable in the web interface. The investigation flow of a single URL follows it.")
H.picture(doc, OUT / "fig_architecture.png", 15.0, "Component architecture of PhishScope")
H.picture(doc, OUT / "fig_flow.png", 15.0, "Investigation flow for one URL")
H2("3.2 Component list")
H.table(doc, ["Component", "Purpose", "Main file(s)", "Input -> output"],
        [["Dataset builder", "build the frozen, de-biased evaluation data", "build_dataset.py", "feeds + ranking -> CSV datasets"],
         ["Passive collectors", "query public sources; cache every answer", "collectors.py", "registered name -> DNS, ASN, RDAP, InternetDB, CT, archive records"],
         ["Batch enrichment", "fill the cache for thousands of names", "enrich.py, enrich_extra.py", "name lists -> SQLite cache"],
         ["Feature extraction", "turn a name and its evidence into numbers", "features.py", "name + cache -> feature row"],
         ["Rule engine", "score a name with 21 weighted rules", "rules_engine.py", "feature row -> score, level, fired rules"],
         ["Campaign matcher", "link names that share rare infrastructure", "campaign.py, graph_corr.py", "IPs, name servers -> matches, clusters"],
         ["Investigation engine", "assemble evidence, run rules, stream steps", "engine.py", "URL -> report"],
         ["Live monitor", "poll feeds, score new names, log latency", "monitor.py", "feeds -> monitor database"],
         ["Command-line tool", "terminal reports", "phishscope.py", "URL -> text/JSON/HTML"],
         ["Web interface", "interactive analysis, dashboards, graph", "webapp.py, webapp/", "browser <-> JSON/stream API"],
         ["Evaluation and ML comparison", "measure rules and models", "evaluate_rules.py, train_*.py, eval_fresh.py", "datasets -> metrics, figures"]],
        [3.2, 4.4, 3.6, 3.8], caption_text="Components of PhishScope")
H2("3.3 Data components and their terms of use")
H.table(doc, ["Source", "Used for", "Terms / licence (as read on 6 Oct 2026)"],
        [["Phishing.Database [24]", "phishing names for training and evaluation", "MIT licence"],
         ["OpenPhish community feed [25]", "unseen-feed test, live monitor", "terms permit academic or independent research; raw data kept local, only derived statistics published"],
         ["PhishStats API [26]", "fresh listings with timestamps", "free for research; anonymous requests capped at 50 per day per IP"],
         ["Tranco list, ID 56WKN [12]", "benign reference names", "research ranking; cite Le Pochat et al."],
         ["URLhaus, abuse.ch [27]", "out-of-distribution malware hosts", "free under abuse.ch fair-use principles"],
         ["RDAP via IANA bootstrap [13]-[15], [23]", "registration data", "public registry services"],
         ["Team Cymru IP-to-ASN mapping [20]", "hosting network", "public DNS interface"],
         ["Shodan InternetDB [21]", "open ports and CVEs of the server IP", "free for non-commercial use, no key"],
         ["crt.sh and Internet Archive [22], [28]", "certificate and archive history (deep mode)", "public, rate-limited services"]],
        [4.4, 4.2, 6.4], caption_text="Data sources")
P("The PhishTank database was not used because automated download requires registering for an application key, which is outside the passive, account-free design of this project.")
H2("3.4 Software and hardware components")
libs = []
for name, label in (("pandas", "pandas"), ("numpy", "NumPy"), ("scikit-learn", "scikit-learn"), ("networkx", "NetworkX"), ("tldextract", "tldextract"), ("requests", "requests"),
                    ("dnspython", "dnspython"), ("Flask", "Flask"), ("rapidfuzz", "RapidFuzz"), ("matplotlib", "Matplotlib"), ("joblib", "joblib")):
    try:
        libs.append([label, md.version(name)])
    except md.PackageNotFoundError:
        pass
H.table(doc, ["Library", "Version used"], [["Python", "3.14.0"]] + libs, [6, 4], caption_text="Software environment")
P("The development and evaluation machine ran Windows 11 Pro; no GPU was used. The web interface is plain HTML, CSS and JavaScript with no external libraries, so it also works offline.")
H2("3.5 Requirements derived from the ethical and legal context")
for t in ("Passive only: no request is ever sent to a listed site. DNS queries about a name can be visible to that name's own name servers; this is stated as a limitation.",
          "No personal data: only domain-level records are processed; WHOIS-style personal contact data is not collected or displayed.",
          "Safe display: phishing names are defanged (example[.]com) by default in every interface and defanged input is accepted.",
          "Respect for services: polite request rates, caching of every answer, identification through a descriptive User-Agent, and no attempt to bypass limits or bot checks.",
          "Honest reporting: results are reported with their uncertainty, and the tool states that a LOW score does not prove a site is safe."):
    B(t)

# ---------------------------------------------------------------- 4 DESIGN AND IMPLEMENTATION
H.page_break(doc)
H1("4. Design and Implementation")
H2("4.1 Design principles")
for t in ("**Passive:** evidence comes only from public services that are queried about the name.", "**Explainable:** every verdict is a sum of named rules with reasons; nothing is hidden in a model.",
          "**Reproducible:** raw data are dated and hashed, all lookups are cached in SQLite and all random choices are seeded.", "**Honest:** the evaluation is designed to expose, not hide, weaknesses."):
    B(t)
H2("4.2 Data design and bias controls")
P(f"The raw snapshot of 6 October 2026 contained {D['phishdb_clean_entries']:,} cleaned phishing host names from Phishing.Database, the Tranco list (ID 56WKN), 258 OpenPhish hosts and a recent URLhaus export. A first, naive dataset exposed several ways in which a detector could look accurate for the wrong reasons. Each was found by inspecting the data and then fixed (table below).")
H.table(doc, ["Problem found", "Evidence", "Fix"],
        [["Different units: Tranco lists registered names, the phishing feed lists full host names with subdomains", f"{pct(D['phishdb_share_with_subdomain'], 0)} of feed entries carry a subdomain, none of the Tranco names do", "use the registered name (eTLD+1) as the unit for both classes"],
         ["Free-hosting platforms", f"{pct(D['phishdb_share_on_shared_platform'], 0)} of feed entries are on shared platforms (e.g. pages.dev, duckdns.org), almost none in Tranco", "treat them separately; report recall only (no fair benign counterpart)"],
         ["Popular benign names are too easy", "top-ranked sites are old, well configured and unlike new phishing", "benign names only from Tranco ranks 100,001-1,000,000; rank is never a feature"],
         ["Repeated base domains", f"{D['phishdb_own_registered_entries']:,} own-registered entries but {D['phishdb_own_registered_unique_names']:,} unique registered names", "de-duplicate by registered name; split by name family"],
         ["Stale snapshot (temporal leak)", f"only {pct(M['dns_resolves_by_class']['phishing'], 0)} of sampled phishing names still resolve (benign {pct(M['dns_resolves_by_class']['benign'], 0)}); {pct(M['rdap_not_found_by_class_before_filter']['phishing'], 0)} are already deleted from the registry", "exclude names that do not resolve or no longer exist: their absence results from takedown, not from anything visible at detection time"],
         ["Registry availability differs by TLD", "some registries (e.g. .ml, .tw) do not offer RDAP", "record 'unavailable' as a value; also report results on RDAP-available names only"]],
        [4.6, 5.4, 5.0], caption_text="Dataset pitfalls found and how they were handled")
P(f"The final lexical corpus has {D['corpus_rows']:,} registered names (50,000 phishing, 50,000 benign). A 2,400-name subset (1,200 per class) was enriched with DNS, hosting and registry lookups; after the resolving/deleted filters {M['rows_after_resolving_filter']['phishing']} phishing and {M['rows_after_resolving_filter']['benign']} benign names remain. The cross-feed test uses {D['openphish_own_registered_not_in_training']} OpenPhish names not in the training data plus {D['crossfeed_negatives']:,} held-out benign names; {D['urlhaus_names_kept']} URLhaus malware hosts and 3,000 shared-platform phishing names are used for out-of-distribution and recall-only checks.")
H2("4.3 Passive collectors")
P("Every collector is one function in collectors.py, wrapped by a decorator that stores its answer in a SQLite table keyed by (kind, key). Timeouts are not cached as facts. The table below lists the sources.")
H.table(doc, ["Collector", "Protocol / endpoint", "Gives", "Notes"],
        [["dns_lookup", "DNS via 1.1.1.1 and 8.8.8.8 (dnspython)", "A, NS, MX, TXT/SPF, TTL", "NXDOMAIN, no-answer and error are distinguished"],
         ["dns_extras", "DNS: _dmarc, www, CAA", "DMARC, www, CAA presence", "cheap signs of a maintained domain"],
         ["asn_lookup", "origin.asn.cymru.com TXT (DNS)", "ASN, prefix, country, AS name", "a DNS query, not a web request"],
         ["rdap_lookup", "IANA bootstrap, then the TLD's RDAP server", "registered / expires / changed, registrar, status, DNSSEC", "per-registry throttling, 429 back-off, 404 = not registered"],
         ["internetdb", "internetdb.shodan.io/<ip>", "open ports, CVEs, hostnames, tags", "weekly refresh; no key"],
         ["crtsh_lookup", "crt.sh JSON (deep mode)", "certificate count, first/last issue, issuers", "slow; single-name use only"],
         ["wayback_first_seen", "archive.org availability API (deep mode)", "was the name ever archived", "single-name use only"]],
        [2.8, 4.8, 4.0, 3.4], caption_text="Passive collectors")
H2("4.4 Feature extraction")
P("Lexical features use only the registered name so that both classes are described the same way: length, digit count and share, hyphens, number of parts, entropy, vowel share, longest consonant and digit runs, punycode, count of scam keywords from a fixed list, whether the name contains a brand, and the edit distance to the nearest of the 500 most popular names in Tranco (a typosquat flag is set at distance 1-2). Network features come from the cache: number of IP addresses, TTL, name-server count and provider, MX/SPF/DMARC/CAA/www presence, TXT-record count, ASN and country, registry age, time to expiry, registration length, DNSSEC, registry hold status, and Shodan port and vulnerability counts. Subdomain-level signals are deliberately kept out of the evaluated machine-learning model and handled by explicit rules.")
H2("4.5 Rule engine")
P("The rule engine is the detection core. Each rule has an identifier, a group (name, registry, DNS, campaign, deep), a plain-English reason, a point value and a test over the feature row. The score of a name is the sum of the points of the rules that fire, capped at 100, and maps to a level: LOW below 25, MEDIUM from 25 to 49, HIGH from 50. The 21 rules are listed in Appendix A. The point values were written down from general phishing-analysis knowledge before any evaluation data were examined and were not tuned afterwards; the list of frequently abused top-level domains (rule N9) is a judgement-based prior, of which only the Freenom country-code domains .tk, .ml, .ga, .cf and .gq are documented in a cited report [19].")
H.code_block(doc, '''@dataclass(frozen=True)
class Rule:
    id: str; group: str; title: str; reason: str; points: int; test: Callable[[dict], bool]

RULES = [
    Rule("N1", "name", "Looks like a misspelt brand", "within 1-2 edits of a very popular name", 25,
         lambda r: bool(r.get("brand_typosquat"))),
    Rule("R1", "registry", "Registered in the last 30 days", "most phishing names are used within days", 30,
         lambda r: _has(r, "age_days") and 0 <= r["age_days"] < 30),
    ...
]

def evaluate(row):
    fired = [(r.id, r.title, r.reason, r.points) for r in RULES if r.test(row)]
    score = min(100, sum(p for *_, p in fired))
    level = next(name for cut, name in LEVELS if score >= cut)      # LEVELS = [(50,"HIGH"), (25,"MEDIUM"), (0,"LOW")]
    return score, fired, level''')
P("Listing: the rule data structure and the scoring function (rules_engine.py, abridged).", size=10.5, italic=True, align=CEN)
H2("4.6 Campaign correlation")
P("Two registered names are linked if they share an IPv4 address, a rare name-server set, a /24 network or a bulk registration (same registrar and registration day), with weights 3, 2, 1 and 3. To prevent big providers from linking everything, any group of more than 40 names is pruned and name-server sets of the 25 most common DNS providers are ignored. Communities of at least three names are found with the Louvain method [9]. For the rules G1 and G2 a name is compared with a reference set of 4,000 phishing-list and 2,000 benign names; an IP or name-server set only counts when at most 15 reference names use it and at least 60% of them are phishing names, so shared hosting never produces a match.")
H2("4.7 Investigation engine and streaming")
P("engine.py parses the input (defanged notation such as hxxps://name[.]tld is accepted), runs the collectors, builds the feature row, applies the rules and assembles the report (score, level, fired rules, evidence, campaign link, notes and a caveat). A streaming variant yields one event after each collector finishes; the Flask server forwards these as Server-Sent Events so the web page can show each lookup completing and each rule firing.")
H2("4.8 Live monitor")
P("monitor.py polls PhishStats (latest 100 listings with timestamps), the OpenPhish community feed and Phishing.Database's 'new in the last hour' list at a fixed interval, scores every new name with the full investigation engine and stores the verdict, the rules that fired and two times: the processing time per name and, where the feed gives a listing time, the delay from listing to verdict. Names listed at most three hours before scoring are classed as fresh; the rest, and the first poll of feeds without timestamps, are baseline. PhishStats' anonymous quota of 50 requests per day limits the polling rate.")
H2("4.9 User interfaces")
P("The command-line tool (phishscope.py) offers investigate, rules, monitor and web commands (Appendix B). The web interface is a single page served by Flask with six tabs: Investigate (live analysis with an animated gauge), Live monitor, Campaign graph (a hand-written force-directed layout on an HTML canvas), Evaluation (charts and a base-rate slider), Rules lab (sliders that recompute detection and false-alarm rates on the labelled data, for exploration only) and How it works (a clickable component diagram). It uses no external libraries so that it runs offline at a demonstration.")
def trim_terminal(path):
    """Copy of a terminal capture without the empty area below the output, so the text is readable at page width (nothing else changes)."""
    import numpy as np
    from PIL import Image
    im = Image.open(path).convert("RGB")
    a = np.asarray(im.convert("L"))
    dark = (a < 110).sum(axis=1) > 2                               # rows that contain text
    rows = np.flatnonzero(dark[60:]) + 60                          # skip the title bar
    gap = int(0.12 * a.shape[0])
    end = rows[0]
    for r in rows[1:]:
        if r - end > gap:                                          # a long blank stretch: the output has ended (taskbar below)
            break
        end = r
    out = OUT / "report_shots" / Path(path).name
    out.parent.mkdir(exist_ok=True)
    im.crop((0, 0, im.width, min(im.height, end + 45))).save(out)
    return out


for key, cap in (("cli_rules.png", "Command line: the rule list (python phishscope.py rules)"), ("cli_investigate_low.png", "Command line: report for an established legitimate domain (LOW)"),
                 ("cli_investigate_high.png", "Command line: report for a name currently listed as phishing (defanged input)"), ("cli_deep.png", "Command line: deep mode (the archive service answered HTTP 429, rate limit, and the tool says so)"),
                 ("ui_investigate_high.png", "Web interface: live investigation of a phishing-list name (score gauge and lookup steps)"),
                 ("ui_investigate_high_b.png", "Web interface: the rules that fired, with reasons, and the passive evidence"),
                 ("ui_monitor.png", "Web interface: live monitor summary"), ("ui_monitor_b.png", "Web interface: live monitor, scored names with the rules that fired"),
                 ("ui_graph.png", "Web interface: campaign graph with one cluster selected"), ("ui_evaluation.png", "Web interface: evaluation charts"),
                 ("ui_evaluation_b.png", "Web interface: operating points on the unseen OpenPhish names and the base-rate explorer at 1% prevalence"),
                 ("ui_lab.png", "Web interface: Rules lab"), ("ui_how.png", "Web interface: clickable component diagram (passive collectors selected)")):
    H.picture(doc, trim_terminal(SHOT / key) if key.startswith("cli_") else SHOT / key, 15.0, cap)
H2("4.10 Machine-learning comparison models")
P("For comparison, logistic regression, histogram gradient boosting and a character n-gram (2-4) logistic regression were trained with scikit-learn [17]. Models were evaluated on a random split and on a template-grouped split in which names that look like members of the same family (digits collapsed, first eight characters) are never shared between training and test; a decision threshold at 1% false-alarm rate was chosen on a separate validation slice. These models never influence a verdict.")
H2("4.11 Testing")
P("Sixteen unit tests cover input parsing (including defanged URLs, shared platforms and rejected input), the rules (a clean site scores zero, a new scam-worded name is HIGH, the score is capped at 100, age rules are mutually exclusive, level boundaries), feature extraction (typosquat flag, entropy, keyword count) and the evaluation helpers (Wilson interval, precision versus prevalence, threshold selection). All pass (screenshot below). In addition, the interface was exercised in a browser while logging JavaScript errors: all six tabs load without errors.")
H.picture(doc, trim_terminal(SHOT / "tests.png"), 15.0, "Unit tests passing")
H2("4.12 Implementation statistics")
import glob
loc = []
for pat, lab in (("src/*.py", "Python source (src/)"), ("webapp/*", "Web interface (HTML, CSS, JavaScript)"), ("tests/*.py", "Unit tests")):
    n = sum(sum(1 for _ in open(f, encoding="utf-8")) for f in glob.glob(str(ROOT / pat)))
    loc.append([lab, f"{len(glob.glob(str(ROOT / pat)))}", f"{n:,}"])
H.table(doc, ["Part", "Files", "Lines"], loc, [8, 3, 3], caption_text="Size of the implementation")

# ---------------------------------------------------------------- 5 RESULTS AND EVALUATION
H.page_break(doc)
H1("5. Results and Evaluation")
H2("5.1 Evaluation design")
P("Five populations are used (table below). Metrics are ROC-AUC, recall (share of phishing names flagged), false-alarm rate (share of benign names flagged) and precision, each at the MEDIUM-or-higher (score at least 25) and HIGH (at least 50) levels, with 95% Wilson confidence intervals. Because phishing is rare in real traffic, precision is also computed for realistic prevalence (Section 5.9).")
H.table(doc, ["Population", "Phishing", "Benign", "Used for"],
        [["Name corpus", "50,000", "50,000", "name-only rules and models (registered names)"],
         ["Live Phishing.Database names", str(R['subset_live_names']['phishing']), str(R['subset_live_names']['n'] - R['subset_live_names']['phishing']), "all rules and models; names that resolve and are still registered"],
         ["OpenPhish live names (unseen feed)", str(R['cross_feed_openphish_live']['positives']), str(R['cross_feed_openphish_live']['n'] - R['cross_feed_openphish_live']['positives']), "generalisation to a different feed"],
         ["URLhaus malware hosts", str(R['urlhaus_malware_live']['n']), "-", "different threat class (recall only)"],
         ["Shared-platform phishing names", "3,000", "-", "name rules only (recall only)"]],
        [4.8, 2.2, 2.2, 5.8], caption_text="Evaluation populations")
H2("5.2 Name-only (lexical) results")
rows = []
for m, v in L["A_ablation"]["template-grouped split"].items():
    rows.append([m, f3(v["roc_auc"]), pct(v["tpr_at_fpr_1pct"]), f3(L["A_ablation"]["random split (by name)"][m]["roc_auc"])])
H.table(doc, ["Model", "AUC (grouped split)", "Recall at 1% false alarms", "AUC (random split)"], rows, [6.2, 3.0, 3.4, 2.8], caption_text="Name-only models on the 100,000-name corpus", align_right_from=1)
top = L["permutation_importance_auc_drop"][:3]
P(f"Names alone are a weak signal once the dataset artefacts are removed: the best model reaches AUC {f3(L['final_model']['template_grouped_test']['roc_auc'])} on unseen name families and catches {pct(L['A_ablation']['template-grouped split']['L3 (HistGradientBoosting)']['tpr_at_fpr_1pct'])} of phishing names at 1% false alarms. The top-level domain dominates the importance ranking ({top[0][0]}: AUC drop {top[0][1]:.3f}), and removing it lowers the AUC from {f3(L['A_ablation']['template-grouped split']['L3 (HistGradientBoosting)']['roc_auc'])} to {f3(L['A_ablation']['template-grouped split']['L3 without TLD (HistGradientBoosting)']['roc_auc'])}. Part of that signal reflects the different geographic mix of the two corpora, so the TLD feature should not be over-interpreted. Random and grouped splits give similar results, so template families did not inflate the figures much. On the unseen OpenPhish feed the name-only model reaches AUC {f3(L['C_cross_feed_openphish']['roc_auc'])} (recall {pct(L['C_cross_feed_openphish']['recall'])} at {pct(L['C_cross_feed_openphish']['fpr'])} false alarms; {L['C_cross_feed_openphish']['positives']} positives).")
H.picture(doc, OUT / "fig_roc_lexical.png", 10.5, "ROC curves of the name-only models on unseen name families")
H2("5.3 What the passive lookups add")
rows = [[k, f3(v["auc_mean"]), f3(v["auc_sd"]), pct(v["tpr_at_fpr_1pct"])] for k, v in M["B_ablation_cv"].items()]
H.table(doc, ["Feature groups (machine-learning model)", "AUC (mean of 3 seeds)", "sd", "Recall at 1% false alarms"], rows, [6.2, 3.2, 1.6, 3.4],
        caption_text="Ablation on live names (5-fold grouped cross-validation)", align_right_from=1)
P(f"DNS records are the strongest single group (AUC {f3(M['B_ablation_cv']['DNS only']['auc_mean'])}), followed by hosting-network information; registry data alone is weak ({f3(M['B_ablation_cv']['RDAP registration only']['auc_mean'])}). Everything together reaches {f3(M['B_ablation_cv']['All features']['auc_mean'])}. The most important single features are the number of TXT records and the DNS time-to-live ({M['permutation_importance_auc_drop'][0][0]}, {M['permutation_importance_auc_drop'][1][0]}). Because Tranco names are established sites, registration age could be an artefact of how the benign class was sampled; a model without any age features still reaches {f3(M['B_ablation_cv']['All features, no age features']['auc_mean'])}, and restricting to names whose registry offers RDAP gives {f3(M['B_all_features_rdap_available_only']['auc_mean'])}.")
H.picture(doc, OUT / "fig_ablation_enriched.png", 11.5, "What the passive lookups add (AUC by feature group)")
H2("5.4 Rule-engine results")
rows = []
for nm, key in (("Name rules, 100,000-name corpus", "corpus_name_rules"), ("Live Phishing.Database names", "subset_live_names"), ("OpenPhish live names (unseen feed)", "cross_feed_openphish_live")):
    for lv, v in R[key]["levels"].items():
        rows.append([nm if lv.startswith("MEDIUM") else "", lv.split(" ")[0], f"{pct(v['recall'])} {ci(v['recall_ci95'])}", f"{pct(v['fpr'])} {ci(v['fpr_ci95'], 1)}", pct(v["precision"], 0)])
H.table(doc, ["Population", "Level", "Recall [95% CI]", "False-alarm rate [95% CI]", "Precision here"], rows, [4.2, 2.3, 3.2, 3.5, 1.9],
        caption_text=f"Rule-engine operating points (ROC-AUC: {f2(R['corpus_name_rules']['roc_auc'])}, {f2(R['subset_live_names']['roc_auc'])} and {f2(R['cross_feed_openphish_live']['roc_auc'])} respectively)")
ga = R["subset_rule_group_auc"]
P(f"With name rules only, the engine is weak (AUC {f2(R['corpus_name_rules']['roc_auc'])}) and almost never reaches HIGH, which is expected: scam-worded or look-alike names are only a minority of phishing. With all rules the AUC is {f2(R['subset_live_names']['roc_auc'])} on live Phishing.Database names. A data-learned weighting of the same rules (logistic regression with cross-validation, for comparison only) reaches {f2(R['subset_learned_weights_cv']['roc_auc'])}, so the hand-set weights leave little on the table. By rule group the AUC is {f2(ga['name'])} (name), {f2(ga['registry'])} (registry), {f2(ga['dns'])} (DNS) and {f2(ga['campaign'])} (campaign link).")
P(f"The registry (age) rules score below chance on this snapshot ({f2(ga['registry'])}). The reason is survivorship: the phishing names that are still alive days after listing are disproportionately compromised, older websites. On live feeds the picture changes (Section 5.8): {pct(FR['groups']['baseline (OpenPhish feed)']['registered_age']['lt30d'], 0) if FR else '39%'} of currently listed OpenPhish names were registered within the last 30 days, against {pct(FR['benign_reference']['lt30d'], 1) if FR else '0.1%'} of benign names. The age rules were therefore kept as designed, not removed after the fact.")
rf = sorted(R["rule_firing_table"], key=lambda r: -r["fires_on_phishing"])
rows = [[r["rule"], r["title"], str(r["points"]), pct(r["fires_on_phishing"]), pct(r["fires_on_benign"]), ("inf" if r["lift"] is None or r["lift"] == float("inf") else f"{r['lift']:.1f}")] for r in rf]
H.table(doc, ["Rule", "Title", "Pts", "Fires on phishing", "Fires on benign", "Lift"], rows, [1.2, 6.0, 1.0, 2.6, 2.4, 1.4],
        caption_text="How often each rule fires on live names (Phishing.Database snapshot)", size=9, align_right_from=2)
H.picture(doc, OUT / "fig_rule_scores.png", 10.5, "Rule-score distribution on live names (dotted: MEDIUM, dashed: HIGH)")
H2("5.5 Unseen feed and other threat classes")
cf = R["cross_feed_openphish_live"]
P(f"On OpenPhish, a feed that was not used to build or tune anything, the rules reach AUC {f2(cf['roc_auc'])} ({cf['positives']} live positives), higher than the machine-learning model trained on Phishing.Database (AUC {f2(M['C_cross_feed_enriched']['roc_auc'])}, recall {pct(M['C_cross_feed_enriched']['recall'])} at {pct(M['C_cross_feed_enriched']['fpr'])} false alarms). The interval is wide because only {cf['positives']} positives were available. URLhaus lists malware hosts, not phishing; the rules flag {pct(R['urlhaus_malware_live']['recall_medium_plus'], 0)} of them at MEDIUM or higher, so PhishScope is a phishing screener rather than a general malware detector. For phishing on free-hosting platforms the name rules flag {pct(R['shared_platform_phishing_name_rules']['recall_medium_plus'], 0)} (MEDIUM or higher), mostly through rule N10; registration age is meaningless for such names.")
H2("5.6 Infrastructure correlation")
sig = GA["share_of_names_linked_by_signal"]
rows = [[n, pct(sig[k]["phishing"]), pct(sig[k]["benign"]), f"{sig[k]['phishing'] / sig[k]['benign']:.1f}x" if sig[k]["benign"] else "-"] for k, n in (("ip", "same IP address"), ("prefix24", "same /24 network"), ("nsset", "same rare name-server set"), ("bulkreg", "bulk registration"))]
H.table(doc, ["Link signal", "Phishing names linked", "Benign names linked", "Ratio"], rows, [5.0, 3.6, 3.4, 2.0],
        caption_text=f"Infrastructure sharing by class ({GA['names_with_dns']:,} resolving names: {GA['phishing_with_dns']:,} phishing, {GA['benign_with_dns']:,} benign)", align_right_from=1)
P(f"Names on the phishing lists share an IP address with another name about {sig['ip']['phishing'] / sig['ip']['benign']:.1f} times as often as benign names, and a rare name-server set {sig['nsset']['phishing'] / sig['nsset']['benign']:.1f} times as often; the /24 signal does not separate the classes and bulk registration is rare. With all four signals the {GA['clusters_ge3']} clusters show no overall enrichment (likelihood ratio {GA['likelihood_ratio_phishing_vs_benign_in_clusters']:.2f}). Keeping only the two discriminating signals, phishing names make up {pct(GS['phishing_share_inside_clusters'], 0)} of the {GS['names_in_clusters_ge3']} clustered names against {pct(GS['baseline_phishing_share_in_sample'], 0)} in the sample (likelihood ratio {GS['likelihood_ratio_phishing_vs_benign_in_clusters']:.1f}), and {pct(GS['pure_phishing_clusters_share'], 0)} of the {GS['clusters_ge3']} clusters are at least 90% phishing. Choosing the two signals after seeing the all-signal result is a post-hoc refinement and is labelled as such; both variants are reported.")
H.picture(doc, OUT / "fig_graph_clusters_specific.png", 11.5, "Largest infrastructure clusters (red: phishing list, green: benign) using IP and name-server links")
H.picture(doc, OUT / "fig_graph_signals.png", 10.5, "Share of names linked, by signal and class")
H2("5.7 Time to verdict")
if FR:
    pa = FR["processing_seconds_all"]
    P(f"Scoring one new name with the full engine (all passive lookups, six names in parallel, uncached, at polite request rates) took a median of {pa['median']:.1f} s per name across {pa['n']} names (mean {pa['mean']:.1f} s, 95th percentile {pa['p95']:.1f} s, maximum {pa['max']:.1f} s). For fresh PhishStats listings the delay from the feed's own listing time to our verdict is dominated by when the feed is polled, not by the analysis"
      + (": in this run all fresh names arrived in the first PhishStats poll, so the delay mainly shows how long they had already been listed when the monitor started." if FR.get("observation", {}).get("feeds", {}).get("phishstats", {}).get("polls_with_new") == 1 else "."))
H2("5.8 Live monitor: fresh and baseline listings")
if FR and FR.get("observation"):
    ob, fd = FR["observation"], FR["observation"]["feeds"]
    later = lambda f: sum(fd[f]["new_per_poll"][1:]) if f in fd else 0
    nfresh = FR["groups"].get("fresh (PhishStats, <=3 h old)", {}).get("levels", {}).get("n", 0)
    P(f"The monitor ran on {ob['date_utc']} from {ob['first_poll_utc']} to {ob['last_poll_utc']} UTC. "
      + (f"The OpenPhish feed was polled {fd['openphish']['polls']} times: the first poll gave the baseline of names listed at that moment and the later polls returned {later('openphish')} new names. " if "openphish" in fd else "")
      + (f"Phishing.Database's 'new in the last hour' list returned {fd['phishdb_new_last_hour']['new_total']} names in {fd['phishdb_new_last_hour']['polls']} polls. " if "phishdb_new_last_hour" in fd else "")
      + (f"PhishStats was polled {fd['phishstats']['polls']} times; it returned {fd['phishstats']['new_per_poll'][0]} new names on the first poll and {later('phishstats')} on later polls. " if "phishstats" in fd else "")
      + f"The window is short and only {nfresh} names qualified as fresh (listed at most three hours before scoring), so the results below describe this window only and are not a measure of long-term performance.")
if FR:
    rows = []
    for g, v in FR["groups"].items():
        dl = v.get("listing_to_verdict_minutes")
        rows.append([g, str(v["levels"]["n"]), pct(v["resolves_share"], 0), pct(v["levels"]["HIGH"]["share"], 0), pct(v["levels"]["MEDIUM_PLUS"]["share"], 0),
                     pct(v["registered_age"]["lt30d"], 0) if v["registered_age"]["lt30d"] is not None else "-", f"{dl['median']:.0f}" if dl else "-"])
    H.table(doc, ["Group", "Names", "Resolve", "HIGH", "MEDIUM+", "Registered <30 d", "Median min listing->verdict"], rows, [4.0, 1.3, 1.5, 1.3, 2.0, 2.3, 2.6],
            caption_text="Live monitor results (all names are listed as phishing by the feeds)", size=9, align_right_from=1)
    b = FR["benign_reference"]
    P(f"All names in this table are phishing according to the feeds, so only recall can be read from it; false alarms were measured on benign live names (MEDIUM or higher: {pct(FR['benign_false_alarm_rates_live_tranco']['MEDIUM+ (score>=25)']['fpr'])}; HIGH: {pct(FR['benign_false_alarm_rates_live_tranco']['HIGH (score>=50)']['fpr'])}). Registration age separates the classes on live listings: {pct(b['lt30d'], 1)} of benign names are younger than 30 days, against {pct(FR['groups']['baseline (OpenPhish feed)']['registered_age']['lt30d'], 0)} of the currently listed OpenPhish names{(' and ' + pct(FR['groups']['fresh (PhishStats, <=3 h old)']['registered_age']['lt30d'], 0) + ' of the fresh PhishStats names') if 'fresh (PhishStats, <=3 h old)' in FR['groups'] else ''}. Comparing groups also shows how much recall depends on the feed: PhishStats listings contain many names on shared platforms and on compromised sites, which the passive rules rate lower. These samples are small and the groups differ, so differences between rows are indicative only.")
    H.picture(doc, OUT / "fig_fresh.png", 15.0, "Live monitor: time to verdict, rule level of listed names and registration age")
H2("5.9 Base-rate analysis")
rows = []
for nm, lv in (("OpenPhish live, MEDIUM+", R["cross_feed_openphish_live"]["levels"]["MEDIUM+ (score>=25)"]), ("OpenPhish live, HIGH", R["cross_feed_openphish_live"]["levels"]["HIGH (score>=50)"])):
    row = [nm]
    for pi in (0.5, 0.05, 0.01, 0.001):
        den = lv["recall"] * pi + lv["fpr"] * (1 - pi)
        row.append(pct(lv["recall"] * pi / den, 1))
    rows.append(row)
H.table(doc, ["Operating point", "50% phishing", "5%", "1%", "0.1%"], rows, [5.0, 2.7, 2.2, 2.2, 2.2],
        caption_text="Share of alerts that are genuine phishing, by prevalence of phishing among the names screened", align_right_from=1)
P("A test set with half phishing, as used above, flatters precision. If only one name in a hundred is phishing, even the HIGH level produces mostly false alarms, which is Axelsson's base-rate fallacy [11]. PhishScope is therefore best used as a triage layer that ranks names for review or combines with other evidence, not as a stand-alone block decision.")
H2("5.10 Rules versus machine learning")
H.table(doc, ["Test", "Rule engine (AUC)", "Machine-learning model (AUC)"],
        [["Live Phishing.Database names", f2(R["subset_live_names"]["roc_auc"]), f"{f2(M['B_ablation_cv']['All features']['auc_mean'])} (cross-validation)"],
         ["OpenPhish live names (unseen feed)", f2(R["cross_feed_openphish_live"]["roc_auc"]), f2(M["C_cross_feed_enriched"]["roc_auc"])],
         ["Names only, 100,000 corpus", f2(R["corpus_name_rules"]["roc_auc"]), f"{f2(L['final_model']['template_grouped_test']['roc_auc'])} (grouped split)"]],
        [6.0, 4.0, 5.0], caption_text="Rules versus machine learning", align_right_from=1)
P("The learned model is better on the old snapshot and on names alone, while the rules generalised better to the unseen feed and give a reason for every alert. Because the two were trained and tested on different populations, the comparison is indicative rather than a controlled benchmark.")
H2("5.11 Threats to validity and limitations")
for t in ("**Stale and biased benchmarks.** The Phishing.Database repository had not been updated since 2 October 2026, so most listed names were already dead; the live-name samples are small and survivors are not representative of all phishing.",
          f"**Small unseen-feed sample.** Only {cf['positives']} live OpenPhish positives were available; confidence intervals are wide.",
          "**Different depth of evidence.** Phishing names in the monitor are scored from full URLs (with subdomain and path rules) while benign reference names are scored at registered-name level.",
          "**Hand-set rules.** The weights are a prior from domain knowledge. They were not tuned on test data, but they may still not be ideal; the learned-weight comparison suggests the loss is small.",
          "**Passive limits.** Without reading the page, a new phishing page on a clean, old, compromised domain scores LOW. Registry data are unavailable for some TLDs, and shared-platform names have no meaningful age.",
          "**Service dependence.** Results rely on free public services whose availability, rate limits and data can change; every lookup is cached so results can be reproduced from the stored data.",
          "**Visibility of DNS queries.** A DNS lookup about a name may be visible to that name's own name servers."):
    B(t)

# ---------------------------------------------------------------- 6 CONCLUSION
H.page_break(doc)
H1("6. Conclusion")
H2("6.1 Conclusion, advantages and disadvantages")
P("PhishScope shows that a transparent, passive, rule-based screener built only from free public data can flag a useful share of live phishing names without ever opening them, explains each alert, links names into infrastructure clusters and scores new listings within seconds. Just as important, the project documents how easily phishing detectors can look better than they are: dataset units, free-hosting platforms, stale feeds and takedown survivorship each changed the picture, and the evaluation reports them instead of hiding them.")
P("Advantages", bold=True, keep_next=True)
for t in ("Safe: never contacts the suspected site, so it can run on live phishing links.", "Explainable: each alert comes with named rules, points and reasons; the web interface lets a user explore how changing a weight changes the outcome.",
          "Reproducible: dated, hashed data, cached lookups, seeded experiments and unit tests.", "Fast and cheap: seconds per name using only free public services.", "Honest: confidence intervals, base-rate analysis and negative findings are part of the report."):
    B(t)
P("Disadvantages", bold=True, keep_next=True)
for t in ("Recall is limited: passive evidence cannot see page content, so many phishing sites score LOW.", "False alarms matter at realistic prevalence; the tool is a triage layer, not a blocker.",
          "Depends on third-party free services with rate limits and changing data.", "Registry age is unavailable for some TLDs and meaningless for shared-platform names.", "Rule weights are hand-set; the TLD-risk list is a judgement prior."):
    B(t)
H2("6.2 Future work")
for t in ("Add page-content and screenshot analysis inside an isolated sandbox, with the owner's permission, to complement the passive evidence.",
          "Collect fresh listings continuously for weeks and learn rule weights with strictly time-based validation.",
          "Track campaigns over time (growth, reuse, takedown) instead of at a single moment, and add certificate-transparency monitoring for newly issued look-alike certificates.",
          "Extend the typosquat comparison to homoglyph and keyboard-distance variants, and to brand lists specific to a country or sector (for example Indian banks).",
          "Package the monitor as a service that feeds a browser extension or a mail-gateway plug-in."):
    B(t)

# ---------------------------------------------------------------- REFERENCES
H.page_break(doc)
H1("References")
refs = [
    "Anti-Phishing Working Group, \"Phishing Activity Trends Report, 1st Quarter 2026,\" published 21 May 2026. [Online]. Available: https://docs.apwg.org/reports/apwg_trends_report_q1_2026.pdf (accessed 6 Oct 2026).",
    "Anti-Phishing Working Group, \"Phishing Activity Trends Report, 2nd Quarter 2026,\" published 28 Aug 2026. [Online]. Available: https://docs.apwg.org/reports/apwg_trends_report_q2_2026.pdf (accessed 6 Oct 2026).",
    "J. Ma, L. K. Saul, S. Savage, and G. M. Voelker, \"Beyond blacklists: learning to detect malicious web sites from suspicious URLs,\" in Proc. ACM SIGKDD Conf. on Knowledge Discovery and Data Mining (KDD), Paris, France, 2009.",
    "D. Sahoo, C. Liu, and S. C. H. Hoi, \"Malicious URL detection using machine learning: a survey,\" arXiv:1701.07179, 2017.",
    "M. Felegyhazi, C. Kreibich, and V. Paxson, \"On the potential of proactive domain blacklisting,\" in Proc. 3rd USENIX Workshop on Large-Scale Exploits and Emergent Threats (LEET), San Jose, CA, Apr. 2010.",
    "S. Hao, A. Kantchelian, B. Miller, V. Paxson, and N. Feamster, \"PREDATOR: Proactive recognition and elimination of domain abuse at time-of-registration,\" in Proc. ACM Conf. on Computer and Communications Security (CCS), 2016.",
    "J. Szurdi, B. Kocso, G. Cseh, J. Spring, M. Felegyhazi, and C. Kanich, \"The long 'taile' of typosquatting domain names,\" in Proc. USENIX Security Symposium, 2014.",
    "V. I. Levenshtein, \"Binary codes capable of correcting deletions, insertions and reversals,\" Soviet Physics Doklady, vol. 10, no. 8, pp. 707-710, 1966.",
    "V. D. Blondel, J.-L. Guillaume, R. Lambiotte, and E. Lefebvre, \"Fast unfolding of communities in large networks,\" J. Stat. Mech.: Theory Exp., 2008, P10008, doi: 10.1088/1742-5468/2008/10/P10008.",
    "D. Arp et al., \"Dos and don'ts of machine learning in computer security,\" in Proc. 31st USENIX Security Symposium, Boston, MA, Aug. 2022.",
    "S. Axelsson, \"The base-rate fallacy and the difficulty of intrusion detection,\" ACM Trans. Inf. Syst. Secur., vol. 3, no. 3, pp. 186-205, Aug. 2000.",
    "V. Le Pochat, T. Van Goethem, S. Tajalizadehkhoob, M. Korczynski, and W. Joosen, \"Tranco: a research-oriented top sites ranking hardened against manipulation,\" in Proc. Network and Distributed System Security Symposium (NDSS), 2019. List ID 56WKN, https://tranco-list.eu/list/56WKN.",
    "S. Hollenbeck and A. Newton, \"Registration Data Access Protocol (RDAP) query format,\" RFC 9082, Internet Engineering Task Force, Jun. 2021.",
    "S. Hollenbeck and A. Newton, \"JSON responses for the Registration Data Access Protocol (RDAP),\" RFC 9083, Internet Engineering Task Force, Jun. 2021.",
    "M. Blanchet, \"Finding the authoritative Registration Data Access Protocol (RDAP) service,\" RFC 9224, Internet Engineering Task Force, Mar. 2022.",
    "B. Laurie, A. Langley, and E. Kasper, \"Certificate Transparency,\" RFC 6962, Internet Engineering Task Force, Jun. 2013 (obsoleted by RFC 9162).",
    "F. Pedregosa et al., \"Scikit-learn: machine learning in Python,\" J. Mach. Learn. Res., vol. 12, pp. 2825-2830, 2011.",
    "A. A. Hagberg, D. A. Schult, and P. J. Swart, \"Exploring network structure, dynamics, and function using NetworkX,\" in Proc. 7th Python in Science Conf. (SciPy), 2008.",
    "Spamhaus Project, \"Spamhaus Botnet Threat Update Q1 2022.\" [Online]. Available: https://content.spamhaus.org/1913347d-b14a-4fb6-8450-befa917f296a.pdf (accessed 6 Oct 2026).",
    "Team Cymru, \"IP to ASN mapping.\" [Online]. Available: https://team-cymru.com/community-services/ip-asn-mapping/ (accessed 6 Oct 2026).",
    "Shodan, \"InternetDB.\" [Online]. Available: https://internetdb.shodan.io/ (accessed 6 Oct 2026).",
    "Internet Archive, \"Wayback Availability JSON API.\" [Online]. Available: https://archive.org/help/wayback_api.php (accessed 6 Oct 2026).",
    "IANA, \"Bootstrap Service Registry for Domain Name Space.\" [Online]. Available: https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml (accessed 6 Oct 2026).",
    "Phishing.Database project. [Online]. Available: https://github.com/Phishing-Database/Phishing.Database (MIT licence; accessed 6 Oct 2026).",
    "OpenPhish, community phishing feed and terms of use. [Online]. Available: https://openphish.com/ (accessed 6 Oct 2026).",
    "PhishStats, phishing database and API. [Online]. Available: https://phishstats.info/ (accessed 6 Oct 2026).",
    "abuse.ch, \"URLhaus.\" [Online]. Available: https://urlhaus.abuse.ch/ (accessed 6 Oct 2026).",
    "Sectigo, \"crt.sh certificate search.\" [Online]. Available: https://crt.sh/ (accessed 6 Oct 2026)."]
for i, r in enumerate(refs, 1):
    p = P(f"[{i}]  {r}", size=11, line=1.15, space_after=4)
    p.paragraph_format.left_indent = H.Cm(1.0)
    p.paragraph_format.first_line_indent = H.Cm(-1.0)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT

# ---------------------------------------------------------------- APPENDICES
H.page_break(doc)
H1("Appendix A: The 21 detection rules")
sys.path.insert(0, str(ROOT / "src"))
import rules_engine as RE  # noqa: E402
rows = [[r.id, r.group, str(r.points), r.title, r.reason] for r in RE.RULES]
H.table(doc, ["ID", "Group", "Pts", "Rule", "Reason"], rows, [1.0, 1.7, 1.0, 4.6, 6.7], size=9, caption_text="All rules with their points (LOW < 25, MEDIUM 25-49, HIGH 50 and above)")
P("Rule U1 (two or more credential words in the URL path, +10 points) is applied by the investigation engine when a full URL is given; it is not part of the registered-name evaluation.")
H1("Appendix B: Command-line reference")
H.code_block(doc, '''python phishscope.py rules
python phishscope.py investigate <url-or-domain> [--deep] [--ml] [--json] [--html report.html]
python phishscope.py monitor [--interval 600] [--max-minutes 60]
python phishscope.py web                  # http://127.0.0.1:5000
python -m unittest discover -s ..\\tests -v''')
P("Defanged input such as hxxps://secure-login[.]example[.]top/verify is accepted. --deep adds certificate-transparency and Internet Archive lookups; --ml adds the optional machine-learning second opinion, which never changes the verdict.")
H1("Appendix C: Reproducing the results")
for i, t in enumerate(("python collect_raw.py   (download the dated snapshot and write the hashed manifest)", "python build_dataset.py   (frozen, de-biased datasets)",
                       "python enrich.py; python enrich_extra.py   (fill the SQLite evidence cache)", "python train_lexical.py; python train_enriched.py   (machine-learning comparison)",
                       "python graph_corr.py make_sample; python enrich.py graph_sample --dns-only; python graph_corr.py analyse [specific]", "python evaluate_rules.py   (rule results and the Rules-lab data)",
                       "python monitor.py --interval 600 --max-minutes 90; python eval_fresh.py   (live monitor and its analysis)", "python make_figures.py   (architecture figures)"), 1):
    H.numbered(doc, t, i, 11)
P("Note: because the lookups concern live infrastructure, a rerun later will see different DNS and registry answers; the stored cache and results in data/ and outputs/ are the record behind the numbers in this report.")

out = ROOT / "report" / "PhishScope_Mini_Project_Report.docx"
doc.save(out)
print("saved", out, "| figures", H.Counter.fig, "tables", H.Counter.tab)
