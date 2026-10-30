"""Small evaluation helpers shared by the experiments (kept separate so the numbers in the report come from one place)."""
import math
import re

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve


def template_group(label):
    """Group names that look like members of one campaign/template family (digits collapsed, first 8 characters)."""
    return re.sub(r"\d+", "#", label)[:8]


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def threshold_at_fpr(y, p, fpr_target=0.01):
    """score threshold whose false-positive rate on the (validation) negatives is <= fpr_target"""
    neg = np.sort(p[y == 0])
    if len(neg) == 0:
        return 0.5
    idx = min(len(neg) - 1, int(math.ceil((1 - fpr_target) * len(neg))))
    return float(neg[idx])


def precision_at_prevalence(tpr, fpr, prevalence):
    denom = tpr * prevalence + fpr * (1 - prevalence)
    return float(tpr * prevalence / denom) if denom > 0 else float("nan")


def summarize(y, p, thr=0.5, boot=0, seed=0):
    y = np.asarray(y)
    p = np.asarray(p)
    pred = p >= thr
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    tpr = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    prec = tp / max(tp + fp, 1)
    f1 = 2 * prec * tpr / max(prec + tpr, 1e-12)
    fprs, tprs, _ = roc_curve(y, p)
    out = {
        "n": int(len(y)), "positives": int(y.sum()), "roc_auc": float(roc_auc_score(y, p)), "pr_auc": float(average_precision_score(y, p)),
        "threshold": float(thr), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": (tp + tn) / len(y), "precision": prec, "recall": tpr, "f1": f1, "fpr": fpr,
        "tpr_at_fpr_1pct": float(np.interp(0.01, fprs, tprs)), "fpr_at_tpr_95pct": float(np.interp(0.95, tprs, fprs)),
        "precision_at_1pct_prevalence_at_thr": precision_at_prevalence(tpr, fpr, 0.01),
        "precision_at_5pct_prevalence_at_thr": precision_at_prevalence(tpr, fpr, 0.05),
    }
    if boot:
        rng = np.random.default_rng(seed)
        aucs = []
        for _ in range(boot):
            idx = rng.integers(0, len(y), len(y))
            if y[idx].min() == y[idx].max():
                continue
            aucs.append(roc_auc_score(y[idx], p[idx]))
        out["roc_auc_ci95"] = [float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))]
    return out
