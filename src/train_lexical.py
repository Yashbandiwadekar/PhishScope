"""Experiment A/C/D/E - lexical detection on the 100k registered-name corpus (no network lookups needed).

A  ablation ladder on two splits (random vs template-grouped) + feature importance
C  cross-feed test: train on Phishing.Database, test on OpenPhish positives + held-out Tranco negatives
D  out-of-distribution: URLhaus malware hosts (not phishing) scored by the phishing model
E  shared-platform phishing names (recall only - no fair benign counterpart exists)
Writes outputs/results_lexical.json, outputs/fig_*.png and models/lexical_model.joblib
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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

import evalkit as K
import features as F

warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parents[1]
PROC, OUT, MOD = ROOT / "data" / "processed", ROOT / "outputs", ROOT / "models"
OUT.mkdir(exist_ok=True)
MOD.mkdir(exist_ok=True)
SEED = 42
brands = F.load_brands()


def build(df):
    X = F.lexical_frame(df["reg"].tolist(), brands)
    return X


def lr_pipe(num, cat=()):
    parts = [("num", StandardScaler(), list(num))]
    if cat:
        parts.append(("cat", OneHotEncoder(min_frequency=30, handle_unknown="infrequent_if_exist"), list(cat)))
    return make_pipeline(ColumnTransformer(parts), LogisticRegression(max_iter=2000, C=1.0))


def hgb_pipe(num, cat=()):
    parts = [("num", "passthrough", list(num))]
    if cat:
        parts.append(("cat", OneHotEncoder(min_frequency=30, handle_unknown="infrequent_if_exist", sparse_output=False), list(cat)))
    return make_pipeline(ColumnTransformer(parts), HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, random_state=SEED))


def ngram_pipe():
    return make_pipeline(TfidfVectorizer(analyzer="char", ngram_range=(2, 4), min_df=5, sublinear_tf=True),
                         LogisticRegression(max_iter=2000, C=3.0))


MODELS = {
    "L1 lexical numeric (LR)": (lambda: lr_pipe(F.NUMERIC_LEXICAL), F.NUMERIC_LEXICAL),
    "L2 + brand-similarity (LR)": (lambda: lr_pipe(F.NUMERIC_LEXICAL + F.BRAND_FEATS), F.NUMERIC_LEXICAL + F.BRAND_FEATS),
    "L3 + TLD (LR)": (lambda: lr_pipe(F.NUMERIC_LEXICAL + F.BRAND_FEATS, ["suffix"]), F.NUMERIC_LEXICAL + F.BRAND_FEATS + ["suffix"]),
    "L3 (HistGradientBoosting)": (lambda: hgb_pipe(F.NUMERIC_LEXICAL + F.BRAND_FEATS, ["suffix"]), F.NUMERIC_LEXICAL + F.BRAND_FEATS + ["suffix"]),
    "L3 without TLD (HistGradientBoosting)": (lambda: hgb_pipe(F.NUMERIC_LEXICAL + F.BRAND_FEATS), F.NUMERIC_LEXICAL + F.BRAND_FEATS),
    "Char n-grams 2-4 (LR)": (ngram_pipe, ["label"]),
}


def fit_predict(name, Xtr, ytr, Xte):
    maker, cols = MODELS[name]
    m = maker()
    if name.startswith("Char"):
        m.fit(Xtr["label"], ytr)
        return m, m.predict_proba(Xte["label"])[:, 1]
    m.fit(Xtr[cols], ytr)
    return m, m.predict_proba(Xte[cols])[:, 1]


def main():
    res = {}
    corpus = pd.read_csv(PROC / "corpus_lexical.csv")
    X = build(corpus)
    y = corpus["label"].values
    groups = X["label"].map(K.template_group).values
    print("features built:", X.shape, flush=True)

    splits = {}
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=0.2, stratify=y, random_state=SEED)
    splits["random split (by name)"] = (tr, te)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr, te = next(gss.split(idx, y, groups))
    splits["template-grouped split"] = (tr, te)
    res["split_sizes"] = {k: {"train": len(v[0]), "test": len(v[1])} for k, v in splits.items()}
    res["template_groups"] = int(len(set(groups)))

    # ---- A: ablation ladder ----------------------------------------------------------------------------------------
    A = {}
    keep = {}
    for sname, (tr, te) in splits.items():
        A[sname] = {}
        for mname in MODELS:
            m, p = fit_predict(mname, X.iloc[tr], y[tr], X.iloc[te])
            A[sname][mname] = K.summarize(y[te], p, thr=0.5, boot=200 if "grouped" in sname else 0)
            keep[(sname, mname)] = (m, p, te)
            print(f"  {sname:<26}{mname:<40} AUC {A[sname][mname]['roc_auc']:.4f}  recall@1%FPR {A[sname][mname]['tpr_at_fpr_1pct']:.3f}", flush=True)
    res["A_ablation"] = A

    # ---- final model = HGB (L3) trained on the template-grouped training part; threshold from a validation slice -----------------
    best_name = "L3 (HistGradientBoosting)"
    tr, te = splits["template-grouped split"]
    tr_fit, tr_val = train_test_split(tr, test_size=0.12, stratify=y[tr], random_state=SEED)
    maker, cols = MODELS[best_name]
    final = maker().fit(X.iloc[tr_fit][cols], y[tr_fit])
    pv = final.predict_proba(X.iloc[tr_val][cols])[:, 1]
    thr = K.threshold_at_fpr(y[tr_val], pv, 0.01)
    pt = final.predict_proba(X.iloc[te][cols])[:, 1]
    res["final_model"] = {"name": best_name, "threshold_at_1pct_fpr_from_validation": thr,
                          "template_grouped_test": K.summarize(y[te], pt, thr=thr, boot=300)}
    print("final model on grouped test:", {k: round(v, 4) for k, v in res["final_model"]["template_grouped_test"].items() if isinstance(v, float)}, flush=True)

    # ---- permutation importance (on 15k test rows) -------------------------------------------------------------------------
    sub = np.random.default_rng(SEED).choice(len(te), 15000, replace=False)
    imp = permutation_importance(final, X.iloc[te].iloc[sub][cols], y[te][sub], n_repeats=3, random_state=SEED, scoring="roc_auc")
    order = np.argsort(imp.importances_mean)[::-1]
    res["permutation_importance_auc_drop"] = [(cols[i], float(imp.importances_mean[i])) for i in order]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    top = order[:12][::-1]
    ax.barh([cols[i] for i in top], [imp.importances_mean[i] for i in top], color="#2f6fa5")
    ax.set_xlabel("drop in ROC-AUC when the feature is shuffled")
    ax.set_title("Lexical model: permutation importance (template-grouped test)")
    fig.tight_layout()
    fig.savefig(OUT / "fig_importance_lexical.png", dpi=170)
    plt.close(fig)

    # ---- ROC curves of the ablation ladder (grouped split) -----------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(6.2, 5))
    for mname in MODELS:
        m, p, te_ = keep[("template-grouped split", mname)]
        fpr, tpr, _ = roc_curve(y[te_], p)
        ax.plot(fpr, tpr, label=f"{mname} (AUC {A['template-grouped split'][mname]['roc_auc']:.3f})")
    ax.plot([0, 1], [0, 1], "k:", lw=0.8)
    ax.set_xlabel("false-positive rate")
    ax.set_ylabel("true-positive rate")
    ax.set_title("Lexical models on unseen name families")
    ax.legend(fontsize=7, loc="lower right")
    fig.tight_layout()
    fig.savefig(OUT / "fig_roc_lexical.png", dpi=170)
    plt.close(fig)

    # ---- final deployable model: refit on ALL corpus rows, keep the validation-chosen threshold ---------------------------------
    deploy = maker().fit(X[cols], y)
    joblib.dump({"model": deploy, "cols": cols, "threshold": thr, "brands": brands, "name": best_name}, MOD / "lexical_model.joblib")

    # ---- C: cross-feed test (model trained on Phishing.Database, tested on OpenPhish) --------------------------------------------------
    cf = pd.read_csv(PROC / "test_crossfeed.csv")
    Xcf = build(cf)
    p_cf = final.predict_proba(Xcf[cols])[:, 1]
    ycf = cf["label"].values
    C = K.summarize(ycf, p_cf, thr=thr, boot=300)
    C["recall_ci95_wilson"] = K.wilson(C["tp"], C["tp"] + C["fn"])
    C["fpr_ci95_wilson"] = K.wilson(C["fp"], C["fp"] + C["tn"])
    res["C_cross_feed_openphish"] = C
    print("cross-feed:", {k: (round(v, 4) if isinstance(v, float) else v) for k, v in C.items() if k in ("n", "positives", "roc_auc", "recall", "fpr")}, flush=True)

    # ---- D: URLhaus malware hosts (out of distribution) ----------------------------------------------------------------------------------
    uh = pd.read_csv(PROC / "test_urlhaus_malware.csv")
    p_uh = final.predict_proba(build(uh)[cols])[:, 1]
    flagged = int((p_uh >= thr).sum())
    res["D_urlhaus_malware"] = {"n": len(uh), "flagged_at_threshold": flagged, "recall": flagged / len(uh), "recall_ci95_wilson": K.wilson(flagged, len(uh)),
                                "median_score": float(np.median(p_uh))}
    # ---- E: shared-platform phishing names (recall only) --------------------------------------------------------------------------------
    sp = pd.read_csv(PROC / "test_sharedplatform_phish.csv")
    p_sp = final.predict_proba(build(sp)[cols])[:, 1]
    fl = int((p_sp >= thr).sum())
    res["E_shared_platform_phishing"] = {"n": len(sp), "flagged_at_threshold": fl, "recall": fl / len(sp), "recall_ci95_wilson": K.wilson(fl, len(sp)),
                                         "note": "the attacker-chosen label is scored on its own; no fair benign counterpart exists, so only recall is reported"}
    print("URLhaus recall", res["D_urlhaus_malware"]["recall"], "| shared-platform recall", res["E_shared_platform_phishing"]["recall"], flush=True)

    # score distribution figure
    fig, ax = plt.subplots(figsize=(6.5, 4))
    bins = np.linspace(0, 1, 41)
    ax.hist(p_cf[ycf == 0], bins=bins, alpha=0.6, density=True, label="held-out benign (Tranco)")
    ax.hist(p_cf[ycf == 1], bins=bins, alpha=0.6, density=True, label="OpenPhish (unseen feed)")
    ax.hist(p_uh, bins=bins, alpha=0.5, density=True, label="URLhaus malware (not phishing)")
    ax.axvline(thr, color="k", ls="--", lw=1, label=f"threshold {thr:.2f}")
    ax.set_xlabel("model score")
    ax.set_ylabel("density")
    ax.legend(fontsize=7)
    ax.set_title("Cross-feed generalisation")
    fig.tight_layout()
    fig.savefig(OUT / "fig_crossfeed_scores.png", dpi=170)
    plt.close(fig)

    (OUT / "results_lexical.json").write_text(json.dumps(res, indent=2, default=float))
    print("saved outputs/results_lexical.json", flush=True)


if __name__ == "__main__":
    main()
