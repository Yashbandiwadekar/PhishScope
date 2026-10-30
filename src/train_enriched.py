"""Experiment B - what do the passive OSINT lookups (DNS, hosting network, RDAP registration data) add?

* 2,400-name subset (1,200 phishing + 1,200 benign registered names), reduced to names that RESOLVE in both classes,
  so "does it resolve?" cannot leak the label (takedowns would otherwise make dead names look malicious).
* Ablation: lexical / DNS / hosting / RDAP / combinations, 5-fold stratified GROUP cross-validation (groups = name
  families), repeated over 3 seeds.
* Confounder check: Tranco names are, by construction, established sites. The age of a name is therefore partly a
  property of how the negatives were sampled. We (1) report a model WITHOUT any age feature, and (2) measure how well
  each model separates the classes inside age bands.
Writes outputs/results_enriched.json, figures, models/enriched_model.joblib
"""
import json
import warnings
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder

import evalkit as K
import features as F

warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parents[1]
PROC, OUT, MOD = ROOT / "data" / "processed", ROOT / "outputs", ROOT / "models"
SEED = 42
brands = F.load_brands()

LEX_NUM = F.NUMERIC_LEXICAL + F.BRAND_FEATS
AGE = ["age_days", "expires_in_days", "days_since_change", "registration_years"]
GROUPS = {
    "LEX": (LEX_NUM, ["suffix"]),
    "DNS": (F.DNS_FEATS, []),
    "HOST": (F.HOST_NUM, F.HOST_CATS),
    "RDAP": (F.RDAP_NUM, F.RDAP_CATS),
}


def pipe(num, cat):
    parts = []
    if num:
        parts.append(("num", "passthrough", num))
    if cat:
        parts.append(("cat", OneHotEncoder(min_frequency=10, handle_unknown="infrequent_if_exist", sparse_output=False), cat))
    return make_pipeline(ColumnTransformer(parts), HistGradientBoostingClassifier(max_iter=200, learning_rate=0.06, max_depth=6, random_state=SEED))


def cols_for(names, drop=()):
    num, cat = [], []
    for g in names:
        n, c = GROUPS[g]
        num += [x for x in n if x not in drop]
        cat += [x for x in c if x not in drop]
    return num, cat


def frame(df):
    lex = F.lexical_frame(df["reg"].tolist(), brands)
    net = F.network_frame(df["reg"].tolist()).drop(columns=["reg"])
    return pd.concat([lex.reset_index(drop=True), net.reset_index(drop=True)], axis=1)


def cv_oof(D, y, groups, num, cat, seeds=(1, 2, 3)):
    aucs, oof_all = [], []
    for s in seeds:
        oof = np.zeros(len(y))
        skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=s)
        for tr, te in skf.split(D, y, groups):
            m = pipe(num, cat).fit(D.iloc[tr][num + cat], y[tr])
            oof[te] = m.predict_proba(D.iloc[te][num + cat])[:, 1]
        aucs.append(roc_auc_score(y, oof))
        oof_all.append(oof)
    return aucs, np.mean(oof_all, axis=0)


def main():
    res = {}
    sub = pd.read_csv(PROC / "subset_enrich.csv")
    D = frame(sub)
    y = sub["label"].values
    res["subset_rows"] = int(len(sub))
    res["dns_resolves_by_class"] = {"benign": float(D.dns_ok[y == 0].mean()), "phishing": float(D.dns_ok[y == 1].mean())}
    res["rdap_not_found_by_class_before_filter"] = {"benign": float((D.rdap_status[y == 0] == "not_found").mean()), "phishing": float((D.rdap_status[y == 1] == "not_found").mean())}
    # names deleted from the registry after takedown are absent only BECAUSE they were phished and removed -> exclude (temporal leak)
    keep = ((D.dns_ok == 1) & (D.rdap_status != "not_found")).values
    res["rows_dropped_not_resolving_or_deleted"] = {"benign": int((~keep & (y == 0)).sum()), "phishing": int((~keep & (y == 1)).sum())}
    D, y = D[keep].reset_index(drop=True), y[keep]
    res["rows_after_resolving_filter"] = {"benign": int((y == 0).sum()), "phishing": int((y == 1).sum())}
    res["rdap_ok_by_class"] = {"benign": float(D.rdap_ok[y == 0].mean()), "phishing": float(D.rdap_ok[y == 1].mean())}
    res["rdap_status_counts"] = {"benign": D.rdap_status[y == 0].value_counts().to_dict(), "phishing": D.rdap_status[y == 1].value_counts().to_dict()}
    print(res["rows_after_resolving_filter"], "RDAP ok:", res["rdap_ok_by_class"], flush=True)
    groups = D["label"].map(K.template_group).values

    configs = {
        "Lexical only": (["LEX"], ()),
        "DNS only": (["DNS"], ()),
        "Hosting network only": (["HOST"], ()),
        "RDAP registration only": (["RDAP"], ()),
        "Lexical + DNS": (["LEX", "DNS"], ()),
        "Lexical + Hosting": (["LEX", "HOST"], ()),
        "Lexical + RDAP": (["LEX", "RDAP"], ()),
        "All features": (["LEX", "DNS", "HOST", "RDAP"], ()),
        "All features, no age features": (["LEX", "DNS", "HOST", "RDAP"], AGE),
    }
    B, oofs = {}, {}
    for name, (gs, drop) in configs.items():
        num, cat = cols_for(gs, drop)
        aucs, oof = cv_oof(D, y, groups, num, cat)
        s = K.summarize(y, oof, thr=0.5)
        B[name] = {"auc_mean": float(np.mean(aucs)), "auc_sd": float(np.std(aucs)), "tpr_at_fpr_1pct": s["tpr_at_fpr_1pct"], "fpr_at_tpr_95pct": s["fpr_at_tpr_95pct"], "pr_auc": s["pr_auc"]}
        oofs[name] = oof
        print(f"  {name:<34} AUC {np.mean(aucs):.4f} ± {np.std(aucs):.4f}   recall@1%FPR {s['tpr_at_fpr_1pct']:.3f}", flush=True)
    res["B_ablation_cv"] = B

    # restricted to names whose TLD registry answers RDAP (removes the "RDAP available" artefact)
    ok = (D.rdap_ok == 1).values
    num, cat = cols_for(["LEX", "DNS", "HOST", "RDAP"])
    aucs, oof_r = cv_oof(D[ok].reset_index(drop=True), y[ok], groups[ok], num, cat)
    res["B_all_features_rdap_available_only"] = {"n": int(ok.sum()), "positives": int(y[ok].sum()), "auc_mean": float(np.mean(aucs)), "auc_sd": float(np.std(aucs))}
    num2, cat2 = cols_for(["LEX", "DNS", "HOST", "RDAP"], AGE)
    aucs2, _ = cv_oof(D[ok].reset_index(drop=True), y[ok], groups[ok], num2, cat2)
    res["B_no_age_rdap_available_only"] = {"auc_mean": float(np.mean(aucs2)), "auc_sd": float(np.std(aucs2))}

    # age bands: does the model still separate the classes among names of similar age?
    age_y = D.age_days.values
    bands = {"registered < 1 year ago": (0, 365), "1-3 years": (365, 1095), "3-8 years": (1095, 2920), "> 8 years": (2920, 1e9)}
    band_res = {}
    for bname, (lo, hi) in bands.items():
        m = (age_y >= lo) & (age_y < hi)
        if m.sum() > 30 and 0 < y[m].sum() < m.sum():
            band_res[bname] = {"n": int(m.sum()), "phishing_share": float(y[m].mean()),
                               "auc_all_features": float(roc_auc_score(y[m], oofs["All features"][m])),
                               "auc_no_age_features": float(roc_auc_score(y[m], oofs["All features, no age features"][m]))}
    res["B_age_bands"] = band_res
    print("age bands:", json.dumps(band_res), flush=True)

    # final model: all features, fitted on every resolving subset row; threshold = 1 % FPR on out-of-fold scores
    num, cat = cols_for(["LEX", "DNS", "HOST", "RDAP"])
    final = pipe(num, cat).fit(D[num + cat], y)
    thr = K.threshold_at_fpr(y, oofs["All features"], 0.01)
    ben = D[y == 0]
    ref = {c: float(ben[c].median()) for c in num}
    ref.update({c: ben[c].mode().iloc[0] for c in cat})
    joblib.dump({"model": final, "num": num, "cat": cat, "threshold": thr, "brands": brands, "ref": ref, "name": "PhishScope enriched HGB"}, MOD / "enriched_model.joblib")
    res["final_enriched_threshold_at_1pct_fpr_oof"] = thr

    # importance on a grouped hold-out
    skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=7)
    tr, te = next(skf.split(D, y, groups))
    m = pipe(num, cat).fit(D.iloc[tr][num + cat], y[tr])
    imp = permutation_importance(m, D.iloc[te][num + cat], y[te], n_repeats=10, random_state=SEED, scoring="roc_auc")
    order = np.argsort(imp.importances_mean)[::-1]
    names_all = num + cat
    res["permutation_importance_auc_drop"] = [(names_all[i], float(imp.importances_mean[i])) for i in order]

    # ---- cross-feed test with the enriched model --------------------------------------------------------------------------------------
    cf = pd.read_csv(PROC / "test_crossfeed.csv")
    Dcf = frame(cf)
    ycf = cf["label"].values
    resolves = ((Dcf.dns_ok == 1) & (Dcf.rdap_status != "not_found")).values
    Dcf, ycf = Dcf[resolves].reset_index(drop=True), ycf[resolves]
    p = final.predict_proba(Dcf[num + cat])[:, 1]
    C = K.summarize(ycf, p, thr=thr, boot=300)
    C["recall_ci95_wilson"] = K.wilson(C["tp"], C["tp"] + C["fn"])
    C["fpr_ci95_wilson"] = K.wilson(C["fp"], C["fp"] + C["tn"])
    C["resolving_share"] = float(resolves.mean())
    res["C_cross_feed_enriched"] = C
    uh = pd.read_csv(PROC / "test_urlhaus_malware.csv")
    Du = frame(uh)
    Du = Du[(Du.dns_ok == 1) & (Du.rdap_status != "not_found")].reset_index(drop=True)
    pu = final.predict_proba(Du[num + cat])[:, 1]
    fl = int((pu >= thr).sum())
    res["D_urlhaus_enriched"] = {"n_resolving": int(len(Du)), "flagged": fl, "recall": fl / max(len(Du), 1), "recall_ci95_wilson": K.wilson(fl, len(Du))}
    print("enriched cross-feed:", {k: (round(v, 4) if isinstance(v, float) else v) for k, v in C.items() if k in ("n", "positives", "roc_auc", "recall", "fpr")}, flush=True)
    print("enriched URLhaus recall:", res["D_urlhaus_enriched"], flush=True)

    # ---- figures --------------------------------------------------------------------------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    names = list(B)
    ax.barh(names[::-1], [B[n]["auc_mean"] for n in names][::-1], xerr=[B[n]["auc_sd"] for n in names][::-1], color="#2f6fa5")
    ax.set_xlim(0.5, 1.0)
    ax.set_xlabel("ROC-AUC (5-fold grouped CV, mean of 3 seeds)")
    ax.set_title("What the passive OSINT lookups add")
    for i, n in enumerate(names[::-1]):
        ax.text(B[n]["auc_mean"] + 0.004, i, f"{B[n]['auc_mean']:.3f}", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "fig_ablation_enriched.png", dpi=170)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.5, 4))
    bins = np.logspace(0, 4.3, 36)
    for lab, name, col in ((0, "benign (Tranco, deep ranks)", "#4c9f70"), (1, "phishing (Phishing.Database)", "#c0392b")):
        a = D.age_days.values[(y == lab) & (D.age_days.values > 0)]
        ax.hist(a, bins=bins, alpha=0.6, label=f"{name} (n={len(a)})", color=col)
    ax.set_xscale("log")
    ax.set_xlabel("domain age at lookup time (days, log scale)")
    ax.set_ylabel("names")
    ax.legend(fontsize=7)
    ax.set_title("Registration age by class (RDAP)")
    fig.tight_layout()
    fig.savefig(OUT / "fig_age_distribution.png", dpi=170)
    plt.close(fig)

    top = order[:14][::-1]
    fig, ax = plt.subplots(figsize=(7, 4.8))
    ax.barh([names_all[i] for i in top], [imp.importances_mean[i] for i in top], color="#2f6fa5")
    ax.set_xlabel("drop in ROC-AUC when the feature is shuffled")
    ax.set_title("Enriched model: permutation importance (grouped hold-out)")
    fig.tight_layout()
    fig.savefig(OUT / "fig_importance_enriched.png", dpi=170)
    plt.close(fig)

    (OUT / "results_enriched.json").write_text(json.dumps(res, indent=2, default=float))
    print("saved outputs/results_enriched.json", flush=True)


if __name__ == "__main__":
    main()
