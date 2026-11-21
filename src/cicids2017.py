"""Run the same models on a second, newer dataset: CIC-IDS2017 with corrected labels.

Dataset: CICIDS2017_improved (Engelen et al., KU Leuven DistriNet, 2023), CICFlowMeter flows from
five working days. Download with data/download_cicids2017.sh.

Split, built like NSL-KDD's (known attacks plus attack types never seen in training):
  train = 70% of Monday-Wednesday (stratified by label)
  test  = the other 30% of Monday-Wednesday (known attack types)
        + all of Thursday-Friday (benign traffic of later days, and attack types not in training)
"Attempted" flows (attack traffic with no malicious effect) count as benign, as the authors advise.
IPs, ports, flow ID and timestamp are dropped so models cannot learn the lab's addresses.

Outputs (results/cicids2017/): dataset_summary.json, metrics_binary.csv, per_attack_recall.csv, hybrid.csv
"""
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from common import DATA, ENSEMBLE
from train_evaluate import SEED, binary_metrics, build_models

SRC = DATA / "cicids2017"
OUT = Path(__file__).resolve().parent.parent / "results" / "cicids2017"
TRAIN_DAYS, LATER_DAYS = ("monday", "tuesday", "wednesday"), ("thursday", "friday")
DROP = ["id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp", "Label", "Attempted Category"]
BENIGN = "BENIGN"


def load_day(day):
    df = pd.read_csv(SRC / f"{day}.csv")
    df.loc[df["Attempted Category"] != -1, "Label"] = BENIGN
    df["day"] = day
    return df


def signed_log(X):
    X = np.nan_to_num(np.asarray(X, dtype=np.float64), nan=0.0, posinf=0.0, neginf=0.0)
    return np.sign(X) * np.log1p(np.abs(X))


def make_preprocessor(scale=True):
    steps = [("log", FunctionTransformer(signed_log))]
    if scale:
        steps.append(("scale", StandardScaler()))
    return Pipeline(steps)


def split():
    early = pd.concat([load_day(d) for d in TRAIN_DAYS], ignore_index=True)
    later = pd.concat([load_day(d) for d in LATER_DAYS], ignore_index=True)
    train, held = train_test_split(early, test_size=0.3, stratify=early.Label, random_state=SEED)
    test = pd.concat([held, later], ignore_index=True)
    for df in (train, test):
        df["is_attack"] = (df.Label != BENIGN).astype(int)
    test["unseen_attack"] = (~test.Label.isin(train.Label.unique())).astype(int)
    return train.reset_index(drop=True), test


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    train, test = split()
    feats = [c for c in train.columns if c not in DROP + ["day", "is_attack", "unseen_attack"]]
    X_tr, y_tr = train[feats], train.is_attack.values
    X_te, y_te = test[feats], test.is_attack.values
    unseen_types = sorted(set(test.Label) - set(train.Label))
    assert BENIGN not in unseen_types and unseen_types, "Thursday-Friday must add attack types"
    (OUT / "dataset_summary.json").write_text(json.dumps({
        "source": "CICIDS2017_improved.zip, https://intrusion-detection.distrinet-research.be/CNS2022/",
        "features": len(feats), "train_rows": len(train), "test_rows": len(test),
        "train_attack_share": float(y_tr.mean()), "test_attack_share": float(y_te.mean()),
        "unseen_attack_types": unseen_types, "unseen_attack_rows": int(test.unseen_attack.sum()),
        "train_label_counts": train.Label.value_counts().to_dict(),
        "test_label_counts": test.Label.value_counts().to_dict(),
    }, indent=2))

    # SVM with RBF kernel scales badly; train it on a stratified 25k sample, as on NSL-KDD
    svm_idx = train.groupby("Label", group_keys=False).sample(frac=25000 / len(train), random_state=SEED).index
    rows, probas = [], {}
    for name, model in build_models(make_preprocessor).items():
        Xf, yf = (X_tr.loc[svm_idx], y_tr[svm_idx]) if name.startswith("SVM") else (X_tr, y_tr)
        t0 = time.perf_counter(); model.fit(Xf, yf); train_s = time.perf_counter() - t0
        t0 = time.perf_counter(); proba = model.predict_proba(X_te)[:, 1]; infer_s = time.perf_counter() - t0
        m = binary_metrics(y_te, (proba >= 0.5).astype(int), proba)
        m.update(model=name, train_rows=len(Xf), train_seconds=train_s, records_per_second=len(X_te) / infer_s)
        rows.append(m); probas[name] = proba
        print(f"{name}: F1={m['f1']:.3f} recall={m['recall']:.3f} FPR={m['false_positive_rate']:.4f} ({train_s:.0f}s)")
    ens = np.mean([probas[n] for n in ENSEMBLE], axis=0)
    m = binary_metrics(y_te, (ens >= 0.5).astype(int), ens)
    m.update(model="Ensemble (RF+GB+MLP)", train_rows=len(X_tr),
             train_seconds=sum(r["train_seconds"] for r in rows if r["model"] in ENSEMBLE), records_per_second=np.nan)
    rows.append(m); probas["Ensemble (RF+GB+MLP)"] = ens
    res = pd.DataFrame(rows).set_index("model")
    res.to_csv(OUT / "metrics_binary.csv", float_format="%.6f")
    print(res[["precision", "recall", "f1", "false_positive_rate", "roc_auc"]].round(4))

    # Recall per attack type, and over all seen / unseen attack rows
    rec = []
    for name, proba in probas.items():
        pred = proba >= 0.5
        for label, g in test[test.is_attack == 1].groupby("Label"):
            rec.append({"model": name, "label": label, "attack_types": "unseen" if g.unseen_attack.iat[0] else "seen",
                        "rows": len(g), "recall": pred[g.index].mean()})
        for flag, kind in ((0, "seen"), (1, "unseen")):
            mask = (test.is_attack == 1) & (test.unseen_attack == flag)
            rec.append({"model": name, "label": "ALL", "attack_types": kind, "rows": int(mask.sum()),
                        "recall": pred[mask.values].mean()})
    pd.DataFrame(rec).to_csv(OUT / "per_attack_recall.csv", index=False, float_format="%.6f")

    # Anomaly layer, as in guardrails.py: Isolation Forest on benign training flows, 5% alert budget
    prep = make_preprocessor().fit(X_tr)
    benign_tr = prep.transform(X_tr[y_tr == 0])
    iso = IsolationForest(n_estimators=300, random_state=SEED, n_jobs=-1).fit(benign_tr)
    cut = np.quantile(-iso.score_samples(benign_tr), 0.95)
    anomaly = -iso.score_samples(prep.transform(X_te)) > cut
    supervised = ens >= 0.5
    unseen = test.unseen_attack.values == 1
    seen = (y_te == 1) & ~unseen
    benign = y_te == 0
    layer = [{"detector": name, "recall_all": recall_score(y_te, p), "recall_seen_attacks": p[seen].mean(),
              "recall_unseen_attacks": p[unseen].mean(), "false_positive_rate": p[benign].mean(),
              "precision": precision_score(y_te, p), "f1": f1_score(y_te, p)}
             for name, p in (("Supervised ensemble", supervised), ("Anomaly (Isolation Forest)", anomaly),
                             ("Hybrid (either layer)", supervised | anomaly))]
    layer = pd.DataFrame(layer)
    layer.to_csv(OUT / "hybrid.csv", index=False, float_format="%.6f")
    print(layer.round(4))


if __name__ == "__main__":
    main()
