"""Evaluate the rule engine honestly.

Datasets (all built before looking at any rule results):
  corpus   100k registered names (50k phishing / 50k benign)      -> NAME rules only
  subset   enriched names that still resolve and are still registered (the realistic population of live phishing)
  cross    OpenPhish names (different feed) + held-out benign       -> unseen-feed generalisation
  urlhaus  malware hosts (not phishing)                            -> recall of the rules on a different threat class
  shared   phishing names on shared platforms                       -> recall only
Also reports: per-rule firing rates, a data-learned weighting (logistic regression on rule triggers, comparison only) and the
ML results already computed, so rules and ML can be compared side by side.
"""
import json
import warnings
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

import campaign
import evalkit as K
import features as F
import rules_engine as R

warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parents[1]
PROC, OUT = ROOT / "data" / "processed", ROOT / "outputs"
brands = F.load_brands()


def table(df, network=True):
    lex = F.lexical_frame(df["reg"].tolist(), brands).reset_index(drop=True)
    T = lex.copy()
    T["shared_platform"] = df["shared_platform"].values if "shared_platform" in df else 0
    T["brand_in_subdomain"] = 0                      # registered-name level data has no subdomain information
    if network:
        net = F.network_frame(df["reg"].tolist()).drop(columns=["reg"]).reset_index(drop=True)
        T = pd.concat([T, net], axis=1)
        camp = pd.DataFrame([campaign.features(r) for r in df["reg"]])
        T = pd.concat([T, camp], axis=1)
    return T


def level_stats(y, score):
    out = {}
    for name, cut in (("MEDIUM+ (score>=25)", 25), ("HIGH (score>=50)", 50)):
        pred = score >= cut
        tp = int(((pred) & (y == 1)).sum())
        fp = int(((pred) & (y == 0)).sum())
        fn = int(((~pred) & (y == 1)).sum())
        tn = int(((~pred) & (y == 0)).sum())
        tpr, fpr = tp / max(tp + fn, 1), fp / max(fp + tn, 1)
        out[name] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "recall": tpr, "fpr": fpr, "precision": tp / max(tp + fp, 1),
                     "recall_ci95": K.wilson(tp, tp + fn), "fpr_ci95": K.wilson(fp, fp + tn),
                     "precision_at_1pct_prevalence": K.precision_at_prevalence(tpr, fpr, 0.01)}
    return out


def main():
    res = {}
    # ---------------- corpus: name rules only -------------------------------------------------------------------------------------
    corpus = pd.read_csv(PROC / "corpus_lexical.csv")
    Tc = table(corpus, network=False)
    sc, Mc = R.score_table(Tc, use_groups=("name",))
    yc = corpus["label"].values
    res["corpus_name_rules"] = {"n": len(yc), "positives": int(yc.sum()), "roc_auc": float(roc_auc_score(yc, sc)), "levels": level_stats(yc, sc),
                                "score_mean_phishing": float(sc[yc == 1].mean()), "score_mean_benign": float(sc[yc == 0].mean())}
    print("corpus name rules AUC", round(res["corpus_name_rules"]["roc_auc"], 4), flush=True)

    # ---------------- enriched subset (live names) ------------------------------------------------------------------------------------
    sub = pd.read_csv(PROC / "subset_enrich.csv")
    Ts = table(sub)
    keep = ((Ts.dns_ok == 1) & (Ts.rdap_status != "not_found")).values
    Ts, ys, grp = Ts[keep].reset_index(drop=True), sub["label"].values[keep], Ts.loc[keep, "label"].map(K.template_group).values
    scs, Ms = R.score_table(Ts)
    res["subset_live_names"] = {"n": int(len(ys)), "phishing": int(ys.sum()), "roc_auc": float(roc_auc_score(ys, scs)), "levels": level_stats(ys, scs)}
    print("live-subset rules AUC", round(res["subset_live_names"]["roc_auc"], 4), flush=True)
    rows = []
    for rid in Ms.columns:
        ph, be = Ms.loc[ys == 1, rid].mean(), Ms.loc[ys == 0, rid].mean()
        rule = R.RULE_BY_ID[rid]
        rows.append({"rule": rid, "title": rule.title, "points": rule.points, "fires_on_phishing": float(ph), "fires_on_benign": float(be),
                     "lift": float(ph / be) if be > 0 else float("inf")})
    pd.DataFrame(rows).to_csv(OUT / "rule_firing_table.csv", index=False)
    res["rule_firing_table"] = rows

    # data-learned weights (comparison only): logistic regression on the rule triggers with grouped CV
    oof = np.zeros(len(ys))
    for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=1).split(Ms, ys, grp):
        m = LogisticRegression(max_iter=2000, C=0.5).fit(Ms.iloc[tr], ys[tr])
        oof[te] = m.predict_proba(Ms.iloc[te])[:, 1]
    res["subset_learned_weights_cv"] = {"roc_auc": float(roc_auc_score(ys, oof))}
    # per-group contribution: AUC with only one rule group
    grp_auc = {}
    for g in ("name", "registry", "dns", "campaign"):
        s_g, _ = R.score_table(Ts, use_groups=(g,))
        grp_auc[g] = float(roc_auc_score(ys, s_g)) if len(set(s_g)) > 1 else 0.5
    s_ex, _ = R.score_table(Ts, use_groups=("name", "dns", "campaign"))
    grp_auc["all but registry (no RDAP)"] = float(roc_auc_score(ys, s_ex))
    res["subset_rule_group_auc"] = grp_auc
    res["subset_all_rules_auc"] = res["subset_live_names"]["roc_auc"]

    # ---------------- cross-feed -----------------------------------------------------------------------------------------------------------------
    cf = pd.read_csv(PROC / "test_crossfeed.csv")
    Tcf = table(cf)
    kcf = ((Tcf.dns_ok == 1) & (Tcf.rdap_status != "not_found")).values
    ycf = cf["label"].values[kcf]
    scf, Mcf = R.score_table(Tcf[kcf].reset_index(drop=True))
    res["cross_feed_openphish_live"] = {"n": int(len(ycf)), "positives": int(ycf.sum()), "roc_auc": float(roc_auc_score(ycf, scf)), "levels": level_stats(ycf, scf)}
    # name rules only, on ALL cross-feed names (not just live ones)
    scn, _ = R.score_table(Tcf, use_groups=("name",))
    ycn = cf["label"].values
    res["cross_feed_openphish_name_rules_all"] = {"n": int(len(ycn)), "positives": int(ycn.sum()), "roc_auc": float(roc_auc_score(ycn, scn)), "levels": level_stats(ycn, scn)}
    print("cross-feed live rules AUC", round(res["cross_feed_openphish_live"]["roc_auc"], 4), flush=True)

    # ---------------- URLhaus malware & shared-platform phishing -------------------------------------------------------------------------------------
    uh = pd.read_csv(PROC / "test_urlhaus_malware.csv")
    Tu = table(uh)
    ku = ((Tu.dns_ok == 1) & (Tu.rdap_status != "not_found")).values
    su, _ = R.score_table(Tu[ku].reset_index(drop=True))
    res["urlhaus_malware_live"] = {"n": int(ku.sum()), "recall_medium_plus": float((su >= 25).mean()), "recall_high": float((su >= 50).mean()),
                                   "recall_medium_ci95": K.wilson(int((su >= 25).sum()), int(ku.sum()))}
    sp = pd.read_csv(PROC / "test_sharedplatform_phish.csv")
    Tsp = table(sp, network=False)
    ssp, _ = R.score_table(Tsp, use_groups=("name",))
    res["shared_platform_phishing_name_rules"] = {"n": len(sp), "recall_medium_plus": float((ssp >= 25).mean()), "recall_high": float((ssp >= 50).mean())}

    # ---------------- ML comparison (already computed) -------------------------------------------------------------------------------------------------
    try:
        ml = json.load(open(OUT / "results_enriched.json"))
        ml_l = json.load(open(OUT / "results_lexical.json"))
        res["ml_comparison"] = {"lexical_ml_template_grouped_auc": ml_l["final_model"]["template_grouped_test"]["roc_auc"],
                                "enriched_ml_all_features_cv_auc": ml["B_ablation_cv"]["All features"]["auc_mean"],
                                "enriched_ml_crossfeed_auc": ml["C_cross_feed_enriched"]["roc_auc"]}
    except Exception as e:  # noqa: BLE001
        res["ml_comparison"] = {"note": f"ML results not available ({e})"}

    (OUT / "results_rules.json").write_text(json.dumps(res, indent=2, default=float))

    # data for the interactive Rules lab: for every evaluated name, which rules fired (indices) + its label
    rule_ids = list(Ms.columns)
    def pack(M, y_):
        return {"fired": [[int(j) for j in np.flatnonzero(M.values[i])] for i in range(len(M))], "labels": [int(v) for v in y_]}
    lab = {"rules": [{"id": r, "title": R.RULE_BY_ID[r].title, "group": R.RULE_BY_ID[r].group, "reason": R.RULE_BY_ID[r].reason, "points": R.RULE_BY_ID[r].points} for r in rule_ids],
           "datasets": {"Phishing.Database snapshot (live names)": pack(Ms, ys), "OpenPhish feed (live names, unseen feed)": pack(Mcf, ycf)},
           "levels": {"medium": 25, "high": 50}}
    (OUT / "ruleslab.json").write_text(json.dumps(lab))

    # figures: score distributions + rule lift
    fig, ax = plt.subplots(figsize=(6.5, 4))
    bins = np.arange(0, 105, 5)
    ax.hist(scs[ys == 0], bins=bins, alpha=0.6, density=True, label="benign (live)", color="#4c9f70")
    ax.hist(scs[ys == 1], bins=bins, alpha=0.6, density=True, label="phishing (live)", color="#c0392b")
    ax.axvline(25, color="k", ls=":", lw=1)
    ax.axvline(50, color="k", ls="--", lw=1)
    ax.set_xlabel("rule score (points)")
    ax.set_ylabel("density")
    ax.legend(fontsize=8)
    ax.set_title("Rule-score distribution (dotted: MEDIUM, dashed: HIGH)")
    fig.tight_layout()
    fig.savefig(OUT / "fig_rule_scores.png", dpi=170)
    plt.close(fig)

    ft = pd.DataFrame(rows).sort_values("fires_on_phishing", ascending=True).tail(14)
    fig, ax = plt.subplots(figsize=(7.5, 5))
    y = np.arange(len(ft))
    ax.barh(y + 0.2, ft.fires_on_phishing, 0.4, label="phishing", color="#c0392b")
    ax.barh(y - 0.2, ft.fires_on_benign, 0.4, label="benign", color="#4c9f70")
    ax.set_yticks(y)
    ax.set_yticklabels([f"{r.rule}  {r.title[:34]}" for r in ft.itertuples()], fontsize=7)
    ax.set_xlabel("share of names on which the rule fires")
    ax.legend(fontsize=8)
    ax.set_title("How often each rule fires (live names)")
    fig.tight_layout()
    fig.savefig(OUT / "fig_rule_firing.png", dpi=170)
    plt.close(fig)

    def brief(d):
        return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in d.items() if not isinstance(v, (dict, list, tuple))}
    print(json.dumps({k: (brief(v) if isinstance(v, dict) else v) for k, v in res.items() if k not in ("rule_firing_table",)}, indent=1, default=float))
    for k in ("corpus_name_rules", "subset_live_names", "cross_feed_openphish_live"):
        print(k, {n: {a: round(b, 3) for a, b in v.items() if a in ("recall", "fpr", "precision", "precision_at_1pct_prevalence")} for n, v in res[k]["levels"].items()})


if __name__ == "__main__":
    main()
