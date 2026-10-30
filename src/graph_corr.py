"""Infrastructure correlation: link names that share passive-OSINT infrastructure and look for campaign clusters.

Edges between two registered names (weights in brackets):
    same IPv4 address [3]            same /24 network [1]
    same (rare) name-server set [2]  bulk registration: same registrar + same registration day [3]
Hub pruning: any group larger than HUB_MAX members, and name-server sets belonging to the most common DNS providers, are
ignored. Big CDNs and shared hosts would otherwise connect everything to everything.
Communities are found with the Louvain method (Blondel et al. 2008, via NetworkX).

usage: python graph_corr.py make_sample   -> data/processed/graph_sample.csv (names to enrich, DNS only)
       python graph_corr.py analyse       -> outputs/graph_summary.json, graph_clusters.csv, fig_graph_*.png
"""
import json
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd

import collectors as C

ROOT = Path(__file__).resolve().parents[1]
PROC, OUT = ROOT / "data" / "processed", ROOT / "outputs"
HUB_MAX = 40
TOP_DNS_PROVIDERS = 25
W = {"ip": 3, "prefix24": 1, "nsset": 2, "bulkreg": 3}
SEED = 42


def make_sample(n_phish=4000, n_benign=2000):
    corpus = pd.read_csv(PROC / "corpus_lexical.csv")
    used = set(pd.read_csv(PROC / "subset_enrich.csv")["reg"])
    pos = corpus[(corpus.label == 1) & ~corpus.reg.isin(used)].sample(n=n_phish, random_state=SEED)
    neg = corpus[(corpus.label == 0) & ~corpus.reg.isin(used)].sample(n=n_benign, random_state=SEED)
    out = pd.concat([pos, neg], ignore_index=True)
    out.to_csv(PROC / "graph_sample.csv", index=False)
    print(len(out), "names ->", PROC / "graph_sample.csv")


def attributes(regs):
    rows = {}
    for r in regs:
        d = C.cache_get("dns", r)
        if not d or d.get("a_status") != "ok":
            continue
        rd = C.cache_get("rdap", r) or {}
        reg_day = (rd.get("registered") or "")[:10] if rd.get("status") == "ok" else ""
        rows[r] = {"ips": d.get("ips", []), "ns": tuple(sorted(d.get("ns", []))), "registrar": rd.get("registrar") or "", "reg_day": reg_day}
    return rows


def ns_provider(ns):
    from features import _EXTRACT
    e = _EXTRACT(ns)
    return f"{e.domain}.{e.suffix}"


def build_graph(attrs):
    prov_count = Counter(ns_provider(ns[0]) for ns in (a["ns"] for a in attrs.values()) if ns)
    common_providers = {p for p, _ in prov_count.most_common(TOP_DNS_PROVIDERS)}
    groups = defaultdict(lambda: defaultdict(set))
    for r, a in attrs.items():
        for ip in a["ips"]:
            groups["ip"][ip].add(r)
            groups["prefix24"][".".join(ip.split(".")[:3])].add(r)
        if a["ns"] and ns_provider(a["ns"][0]) not in common_providers:
            groups["nsset"][a["ns"]].add(r)
        if a["registrar"] and a["reg_day"]:
            groups["bulkreg"][(a["registrar"], a["reg_day"])].add(r)
    G = nx.Graph()
    stats = {}
    for typ, gd in groups.items():
        used = pruned = 0
        for key, members in gd.items():
            if len(members) < 2:
                continue
            if len(members) > HUB_MAX:
                pruned += 1
                continue
            if W[typ] == 0:
                continue
            used += 1
            for a, b in combinations(sorted(members), 2):
                w = W[typ]
                if G.has_edge(a, b):
                    G[a][b]["weight"] += w
                    G[a][b]["types"].add(typ)
                else:
                    G.add_edge(a, b, weight=w, types={typ})
        stats[typ] = {"groups_used": used, "hub_groups_pruned": pruned}
    return G, stats, common_providers


def analyse(variant="all"):
    global W
    suffix = ""
    if variant == "specific":                      # keep only the signals that separated the classes in the signal analysis
        W = {"ip": 3, "prefix24": 0, "nsset": 2, "bulkreg": 0}
        suffix = "_specific"
    sample = pd.read_csv(PROC / "graph_sample.csv")
    sub = pd.read_csv(PROC / "subset_enrich.csv")
    df = pd.concat([sample[["reg", "label"]], sub[["reg", "label"]]]).drop_duplicates("reg")
    label = dict(zip(df.reg, df.label))
    attrs = attributes(df.reg.tolist())
    print("names with DNS data:", len(attrs), "of", len(df), flush=True)
    G, stats, providers = build_graph(attrs)
    res = {"names_total": int(len(df)), "names_with_dns": len(attrs),
           "phishing_with_dns": int(sum(label[r] for r in attrs)), "benign_with_dns": int(sum(1 - label[r] for r in attrs)),
           "edges": G.number_of_edges(), "linked_nodes": G.number_of_nodes(), "edge_group_stats": stats,
           "common_dns_providers_ignored": sorted(providers)[:TOP_DNS_PROVIDERS]}

    # how many names of each class are linked to at least one other name, per signal
    link_share = {}
    for typ in W:
        linked = set()
        for a, b, d in G.edges(data=True):
            if typ in d["types"]:
                linked.update((a, b))
        ph = [r for r in attrs if label[r] == 1]
        be = [r for r in attrs if label[r] == 0]
        link_share[typ] = {"phishing": sum(r in linked for r in ph) / max(len(ph), 1), "benign": sum(r in linked for r in be) / max(len(be), 1)}
    res["share_of_names_linked_by_signal"] = link_share

    comms = nx.community.louvain_communities(G, weight="weight", seed=SEED, resolution=1.0)
    comms = [c for c in comms if len(c) >= 3]
    base = res["phishing_with_dns"] / max(len(attrs), 1)
    rows = []
    for i, c in enumerate(sorted(comms, key=len, reverse=True)):
        ph = sum(label[r] for r in c)
        sub_g = G.subgraph(c)
        sig = Counter(t for _, _, d in sub_g.edges(data=True) for t in d["types"])
        ips = Counter(ip for r in c for ip in attrs[r]["ips"])
        rows.append({"cluster": i + 1, "size": len(c), "phishing": ph, "phishing_share": ph / len(c), "density": nx.density(sub_g),
                     "top_signal": sig.most_common(1)[0][0] if sig else "", "top_ip": ips.most_common(1)[0][0] if ips else "",
                     "example_names_defanged": ", ".join(sorted(r.replace(".", "[.]") for r in list(c)[:3]))})
    cl = pd.DataFrame(rows)
    cl.to_csv(OUT / f"graph_clusters{suffix}.csv", index=False)
    cid = {}
    for i, c in enumerate(sorted(comms, key=len, reverse=True)):
        for r in c:
            cid[r] = i + 1
    pd.DataFrame([{"reg": r, "label": int(label[r]), "cluster": cid.get(r, 0)} for r in attrs]).to_csv(OUT / f"graph_membership{suffix}.csv", index=False)
    in_c = {r for c in comms for r in c}
    ph_in = sum(label[r] for r in in_c)
    res["clusters_ge3"] = len(comms)
    res["names_in_clusters_ge3"] = len(in_c)
    res["baseline_phishing_share_in_sample"] = base
    res["phishing_share_inside_clusters"] = ph_in / max(len(in_c), 1)
    res["pure_phishing_clusters_share"] = float((cl.phishing_share >= 0.9).mean()) if len(cl) else 0.0
    res["largest_clusters"] = cl.head(8).to_dict("records")
    res["likelihood_ratio_phishing_vs_benign_in_clusters"] = ((ph_in / max(res["phishing_with_dns"], 1)) / max((len(in_c) - ph_in) / max(res["benign_with_dns"], 1), 1e-9))
    (OUT / f"graph_summary{suffix}.json").write_text(json.dumps(res, indent=2, default=float))
    print(json.dumps({k: v for k, v in res.items() if k not in ("largest_clusters", "common_dns_providers_ignored")}, indent=2, default=float), flush=True)

    # figure 1: the largest clusters, coloured by class
    top = [set(c) for c in sorted(comms, key=len, reverse=True)[:6]]
    if top:
        H = G.subgraph(set().union(*top))
        pos = nx.spring_layout(H, seed=SEED, k=0.35, weight="weight")
        fig, ax = plt.subplots(figsize=(8, 6))
        nx.draw_networkx_edges(H, pos, alpha=0.25, width=0.6, ax=ax)
        colors = ["#c0392b" if label[n] == 1 else "#4c9f70" for n in H.nodes]
        nx.draw_networkx_nodes(H, pos, node_color=colors, node_size=22, ax=ax, linewidths=0)
        ax.set_title("Largest infrastructure clusters (red = phishing list, green = benign Tranco)")
        ax.axis("off")
        fig.tight_layout()
        fig.savefig(OUT / f"fig_graph_clusters{suffix}.png", dpi=170)
        plt.close(fig)
    # figure 2: share of names linked by signal
    fig, ax = plt.subplots(figsize=(6.5, 3.8))
    types = list(link_share)
    x = np.arange(len(types))
    ax.bar(x - 0.18, [link_share[t]["phishing"] for t in types], 0.36, label="phishing names", color="#c0392b")
    ax.bar(x + 0.18, [link_share[t]["benign"] for t in types], 0.36, label="benign names", color="#4c9f70")
    ax.set_xticks(x)
    ax.set_xticklabels(["same IP", "same /24", "same name-server set", "bulk registration"], fontsize=8)
    ax.set_ylabel("share of names linked")
    ax.legend(fontsize=8)
    ax.set_title("Infrastructure sharing by class")
    fig.tight_layout()
    fig.savefig(OUT / f"fig_graph_signals{suffix}.png", dpi=170)
    plt.close(fig)


if __name__ == "__main__":
    if sys.argv[1] == "analyse":
        analyse(sys.argv[2] if len(sys.argv) > 2 else "all")
    else:
        make_sample()
