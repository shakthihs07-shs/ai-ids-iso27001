"""AI guardrail tests for the trained IDS models.

1. Threshold tuning      - trade recall against false-positive rate (alert budget)
2. Human-in-the-loop     - route uncertain scores to an analyst queue
3. Anomaly layer         - Isolation Forest trained on normal traffic only, to catch novel attacks
4. Drift monitoring      - Population Stability Index (PSI) between training and live (test) data
5. Evasion robustness    - perturb top features of detected attacks and measure how many slip through

Outputs go to results/guardrails_*.csv|json|png
"""
import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import recall_score, precision_score, f1_score, confusion_matrix

from common import ensemble_score, load, feature_cols, make_preprocessor

SEED = 42
OUT = Path(__file__).resolve().parent.parent / "results"


def fpr(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return fp / (fp + tn)


def psi(expected, actual, bins=10):
    """Population Stability Index. <0.1 stable, 0.1-0.25 moderate shift, >0.25 major shift."""
    qs = np.unique(np.quantile(expected, np.linspace(0, 1, bins + 1)))
    if len(qs) < 3:  # near-constant feature
        return 0.0
    e = np.histogram(np.clip(expected, qs[0], qs[-1]), qs)[0] / len(expected)
    a = np.histogram(np.clip(actual, qs[0], qs[-1]), qs)[0] / len(actual)
    e, a = np.clip(e, 1e-4, None), np.clip(a, 1e-4, None)
    return float(np.sum((a - e) * np.log(a / e)))


def main():
    train, test, _ = load()
    X_tr, X_te, y_te = train[feature_cols()], test[feature_cols()], test["is_attack"].values
    models = joblib.load(OUT / "models.joblib")["models"]
    score = ensemble_score(models, X_te)
    summary = {}

    # 1. Threshold tuning
    rows = []
    for t in [0.9, 0.7, 0.5, 0.3, 0.2, 0.1, 0.05]:
        p = (score >= t).astype(int)
        rows.append({"threshold": t, "recall": recall_score(y_te, p), "precision": precision_score(y_te, p),
                     "f1": f1_score(y_te, p), "false_positive_rate": fpr(y_te, p),
                     "alerts_per_10k_events": 10000 * p.mean()})
    thr = pd.DataFrame(rows)
    thr.to_csv(OUT / "guardrails_threshold.csv", index=False, float_format="%.6f")
    print(thr.round(3))

    # 2. Human-in-the-loop band: auto-block >= 0.7, analyst review 0.2-0.7, auto-allow < 0.2
    hi, lo = 0.7, 0.2
    auto_block, review = score >= hi, (score >= lo) & (score < hi)
    summary["human_in_loop"] = {
        "auto_block_share": float(auto_block.mean()),
        "analyst_review_share": float(review.mean()),
        "auto_allow_share": float((score < lo).mean()),
        "auto_block_precision": float(y_te[auto_block].mean()),
        "review_queue_attack_share": float(y_te[review].mean()),
        "attacks_missed_by_auto_allow": int(((score < lo) & (y_te == 1)).sum()),
        "attacks_total": int(y_te.sum()),
    }

    # 3. Anomaly layer: Isolation Forest fit on NORMAL training traffic only
    prep = make_preprocessor().fit(X_tr)
    iso = IsolationForest(n_estimators=300, contamination="auto", random_state=SEED, n_jobs=-1)
    normal_tr = prep.transform(X_tr[train.is_attack == 0])
    iso.fit(normal_tr)
    # set the anomaly threshold so only 5% of normal TRAINING traffic is flagged (alert budget)
    cut = np.quantile(-iso.score_samples(normal_tr), 0.95)
    anomaly = (-iso.score_samples(prep.transform(X_te)) > cut)
    supervised = score >= 0.5
    hybrid = supervised | anomaly
    unseen = test.unseen_attack.values == 1
    seen_attack = (y_te == 1) & ~unseen
    layer = []
    for name, p in (("Supervised ensemble", supervised), ("Anomaly (Isolation Forest)", anomaly),
                    ("Hybrid (either layer)", hybrid)):
        layer.append({"detector": name, "recall_all": recall_score(y_te, p), "recall_seen_attacks": p[seen_attack].mean(),
                      "recall_unseen_attacks": p[unseen].mean(), "false_positive_rate": fpr(y_te, p),
                      "precision": precision_score(y_te, p), "f1": f1_score(y_te, p)})
    layer = pd.DataFrame(layer)
    layer.to_csv(OUT / "guardrails_hybrid.csv", index=False, float_format="%.6f")
    print(layer.round(3))

    # 4. Drift monitoring with PSI on numeric features. Normal traffic only: the test set has more
    #    attacks (57% vs 46%), and comparing all traffic would report that change in mix as drift.
    num = [c for c in feature_cols() if c not in ("protocol_type", "service", "flag")]
    norm_tr, norm_te = X_tr[train.is_attack == 0], X_te[test.is_attack == 0]
    drift = pd.DataFrame({"feature": num,
                          "psi": [psi(norm_tr[c].values.astype(float), norm_te[c].values.astype(float)) for c in num]})
    drift["status"] = pd.cut(drift.psi, [-1, 0.1, 0.25, 99], labels=["stable", "moderate shift", "major shift"])
    drift.sort_values("psi", ascending=False).to_csv(OUT / "guardrails_drift_psi.csv", index=False, float_format="%.6f")
    summary["drift"] = {"features_major_shift": int((drift.status == "major shift").sum()),
                        "features_moderate_shift": int((drift.status == "moderate shift").sum()),
                        "top_shifted": drift.sort_values("psi", ascending=False).head(5)[["feature", "psi"]].round(3).values.tolist()}
    svc_shift = norm_te.service.value_counts(normalize=True).sub(
        norm_tr.service.value_counts(normalize=True), fill_value=0).abs().sort_values(ascending=False).head(5)
    summary["drift"]["service_mix_largest_changes"] = svc_shift.round(3).to_dict()

    # 5. Evasion robustness: attacker inflates traffic volume/duration to look 'normal'
    detected = test[(y_te == 1) & supervised].copy()
    base_n = len(detected)
    ev = []
    for factor in [1.5, 2, 5, 10]:
        adv = detected[feature_cols()].copy()
        adv["src_bytes"] = (adv["src_bytes"] * factor + 200).round()
        adv["dst_bytes"] = (adv["dst_bytes"] * factor + 200).round()
        adv["duration"] = adv["duration"] + factor
        s = ensemble_score(models, adv)
        ev.append({"perturbation": f"bytes x{factor} +200, duration +{factor}s",
                   "attacks_previously_detected": base_n,
                   "now_evade": int((s < 0.5).sum()), "evasion_rate": float((s < 0.5).mean())})
    ev = pd.DataFrame(ev)
    ev.to_csv(OUT / "guardrails_evasion.csv", index=False, float_format="%.6f")
    print(ev)

    (OUT / "guardrails_summary.json").write_text(json.dumps(summary, indent=2, default=float))
    print(json.dumps(summary, indent=2, default=float))

    fig, ax = plt.subplots(figsize=(5.5, 4))
    ax.plot(thr.false_positive_rate * 100, thr.recall * 100, marker="o")
    for _, r in thr.iterrows():
        ax.annotate(f"t={r.threshold}", (r.false_positive_rate * 100, r.recall * 100), fontsize=8,
                    xytext=(4, -10), textcoords="offset points")
    ax.set_xlabel("False-positive rate (%)"); ax.set_ylabel("Recall / detection rate (%)")
    ax.set_title("Alert threshold trade-off (ensemble)")
    ax.grid(alpha=0.3); fig.tight_layout(); fig.savefig(OUT / "guardrails_threshold.png", dpi=150); plt.close(fig)


if __name__ == "__main__":
    main()
