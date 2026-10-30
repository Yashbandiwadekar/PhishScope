# PhishScope - how it works (viva notes)

Read this once before the viva. Everything here is something the project really does.

## 1. The one-minute explanation

"Scam and phishing sites are created in huge numbers and many are gone within days, so by the time a blocklist lists
one, victims have often already been hit. PhishScope tries to judge a link **before anyone opens it**, using only public
information about the *name*: how it is spelt, when it was registered, which DNS and hosting it uses, and whether the
same infrastructure already hosts known phishing. It adds up points from 21 simple rules and tells you the score and
why. It never visits the page, so it is safe to run on live phishing links."

## 2. The pipeline in six steps

1. **Input** - a URL or domain; defanged text (`hxxps://name[.]tld`) is accepted.
2. **Parse** - split into host, *registered name* (the part someone paid for, e.g. `example.co.uk`), subdomain and path,
   using the Public Suffix List (the private section too, so `x.pages.dev` is recognised as a free-hosting name).
3. **Collect (passive)** - DNS records; hosting network (Team Cymru ASN mapping, itself a DNS query); registry data from
   the TLD's RDAP server (RFC 9082/9083, found through the IANA bootstrap, RFC 9224); Shodan InternetDB for the server's
   open ports; optionally certificate-transparency logs (crt.sh) and Internet Archive history. All results are cached in
   SQLite.
4. **Features** - numbers such as name length, digit share, entropy, closeness to a famous brand, domain age, number of
   TXT records.
5. **Rules** - 21 rules, each with an id, a plain-English reason and points. Example: *N1 looks like a misspelt brand
   (+25)*, *R1 registered in the last 30 days (+30)*. Score = sum of points (max 100). LOW < 25 <= MEDIUM < 50 <= HIGH.
6. **Report** - score, level, which rules fired and why, the raw evidence, and any link to known phishing infrastructure.

## 3. The architecture in four bands (report Figure 1 = the "How it works" tab)

1. **Public data (read only)** - phishing feeds, the Tranco ranking, registries and DNS.
2. **Passive collection** - dataset builder (feeds + Tranco), batch enrichment, passive collectors, SQLite evidence cache.
3. **Analysis** - feature extraction, campaign matcher, rule engine (the core), investigation engine.
4. **Outputs** - ML comparison, evaluation, live monitor, interfaces (CLI, web page, JSON API).

Two long arrows: the live monitor polls the feeds directly, and the frozen test sets go from the dataset builder straight
to the evaluation.

## 4. The other parts

* **Campaign graph** - names are linked if they share an IP or a rare name-server set (big CDNs and shared hosts are
  pruned because they link everything). Louvain community detection finds clusters. With IP + name-server links only,
  phishing names are 52% of clustered names against 34% in the sample, and 23% of clusters are at least 90% phishing.
* **Live monitor** - polls PhishStats, OpenPhish and Phishing.Database, scores each new name, records the time from
  listing to verdict. First-poll entries without timestamps are labelled "baseline". In the recorded run the feeds were
  quiet: after the first poll OpenPhish and Phishing.Database gave no new names, and all 30 fresh PhishStats names came
  in the first poll. So the "minutes from listing to verdict" mostly shows how long they had been listed before the
  monitor started; the real speed of the tool is the processing time per name (about 2 s, including all lookups).
* **Machine learning (comparison only)** - logistic regression, gradient boosting and character n-grams were trained to
  see how a learned model compares. They never change the verdict.
* **Web interface** - Flask serves a JSON API and one page of plain JavaScript; the analysis streams to the page step by
  step using Server-Sent Events.

## 5. Why the numbers are modest (be ready to say this)

* A naive set-up gives ~99% accuracy for free: Tranco lists registered names while phishing feeds list full host names
  with subdomains, and a third of the feed sits on free-hosting platforms. A model can win by counting dots. We compare
  both classes at the registered-name level and evaluate shared-platform names separately.
* The Phishing.Database snapshot was stale: only 27% of the sampled phishing names still resolved (benign: 89%) and
  about half were already deleted from the registry. Deleted names are excluded - their absence is a *result of* the
  takedown, not something visible at detection time.
* Names that survive takedown are often compromised older sites, so registration-age rules did not separate the classes
  on that snapshot (AUC 0.49 for that rule group), but they do on live feeds: 39% of currently listed OpenPhish names were
  registered in the last 30 days against 0.1% of benign names.
* HIGH alerts are precise but rare; MEDIUM+ catches more but raises more false alarms. At realistic phishing prevalence
  most alerts would be false (base-rate fallacy, Axelsson 2000) - the Evaluation tab has a slider that shows this.
* The rule weights were fixed before looking at results and were **not** tuned on test data. The Rules lab lets you
  change them, but that is exploration; tuning on the evaluation data would overfit.

## 6. Questions an examiner may ask - short answers

* **Why rules and not deep learning?** Rules are explainable (every alert comes with reasons), need no labelled training
  data, and held up better on an unseen feed (AUC 0.79 vs 0.74 for the learned model). The learned model is better on
  the old snapshot and is reported as a comparison.
* **Is it legal / safe to run on phishing links?** It never contacts the target. It asks public services (DNS resolvers,
  registries, Shodan's database, certificate logs, the Internet Archive) about the name. A DNS query can be visible to the
  name's own name server - stated as a limitation.
* **What does a LOW score mean?** Only that none of the rules fired. A new phishing site on a clean, old, compromised
  domain would score LOW. Passive screening is one layer, not a guarantee.
* **What is RDAP?** The modern, JSON replacement for WHOIS (RFC 9082/9083). Each TLD's registry runs a server; IANA's
  bootstrap file says which one (RFC 9224). Some TLDs (e.g. .ml, .tw) do not offer it, so age rules cannot apply to them.
* **What is certificate transparency?** Public append-only logs of issued TLS certificates (RFC 6962). A name whose first
  certificate is days old is a weak signal of a brand-new site (rule C1, deep mode only).
* **What is a typosquat?** A name one or two edits from a popular brand (Levenshtein distance). Rule N1 compares the name
  with the 500 most popular names in the Tranco list.
* **What is defanging?** Writing `hxxp://name[.]tld` so nobody clicks a malicious link by accident. The tool accepts and
  shows defanged names.
* **What would you do next?** Add page-content analysis in an isolated sandbox (with permission), learn rule weights with
  proper time-based validation, and track campaigns over time instead of at one moment.

## 7. Numbers worth remembering (all from the saved results)

| What | Value |
|---|---|
| Lexical corpus | 100,000 registered names (50,000 phishing, 50,000 benign) |
| Rules | 21; LOW < 25, MEDIUM 25-49, HIGH 50+ |
| Rules on live Phishing.Database names | AUC 0.64 (ML 0.77) |
| Rules on unseen OpenPhish feed (live names) | AUC 0.79; HIGH catches 19.4% at 0.6% false alarms; MEDIUM+ catches 48.4% at 11.2% |
| Registered in the last 30 days | 39% of live OpenPhish names vs 0.1% of benign |
| Graph (IP + name-server links) | phishing 52% of clustered names vs 34% baseline; 2.1x enrichment |
| Live monitor run | 30 fresh PhishStats names; MEDIUM+ 23%, HIGH 10%; about 2 s processing per name |
| Unit tests | 16 passing |
