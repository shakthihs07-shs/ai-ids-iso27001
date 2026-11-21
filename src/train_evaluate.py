"""Train and evaluate four IDS models plus a soft-voting ensemble on NSL-KDD.

Outputs (results/):
  metrics_binary.csv       - attack vs normal on KDDTest+
  cv_binary.csv            - 5-fold CV on KDDTrain+ (in-distribution, 'lab' numbers)
  per_category_recall.csv  - recall per attack family, seen vs unseen attacks
  multiclass_report.txt    - 5-class report for the best model
  feature_importance.csv   - Random Forest top features
  confusion_*.png, roc.png
  models.joblib            - fitted pipelines for the guardrail tests
"""
import json
import time
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier, VotingClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, confusion_matrix, classification_report,
                             ConfusionMatrixDisplay, RocCurveDisplay)
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC

from common import ENSEMBLE, load, feature_cols, make_preprocessor

SEED = 42
OUT = Path(__file__).resolve().parent.parent / "results"
OUT.mkdir(exist_ok=True)


def build_models(prep=make_preprocessor):
    """prep(scale) returns the preprocessing step, so other datasets reuse the same models."""
    return {
        "Random Forest": Pipeline([("prep", prep(scale=False)),
                                   ("clf", RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=SEED))]),
        "Gradient Boosting": Pipeline([("prep", prep(scale=False)),
                                       ("clf", HistGradientBoostingClassifier(max_iter=300, random_state=SEED))]),
        "SVM (RBF)": Pipeline([("prep", prep()),
                               ("clf", SVC(C=10, gamma="scale", probability=True, random_state=SEED))]),
        "Neural Net (MLP)": Pipeline([("prep", prep()),
                                      ("clf", MLPClassifier(hidden_layer_sizes=(128, 64), early_stopping=True,
                                                            max_iter=200, random_state=SEED))]),
    }


def binary_metrics(y, pred, proba):
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred),
        "recall": recall_score(y, pred),
        "f1": f1_score(y, pred),
        "false_positive_rate": fp / (fp + tn),
        "roc_auc": roc_auc_score(y, proba),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
    }


def main():
    train, test, unseen = load()
    X_tr, y_tr = train[feature_cols()], train["is_attack"]
    X_te, y_te = test[feature_cols()], test["is_attack"]
    info = {
        "train_rows": len(train), "test_rows": len(test),
        "train_attack_share": float(y_tr.mean()), "test_attack_share": float(y_te.mean()),
        "attack_types_train": int(train.loc[train.is_attack == 1, "label"].nunique()),
        "attack_types_test": int(test.loc[test.is_attack == 1, "label"].nunique()),
        "unseen_attack_types": unseen,
        "unseen_attack_rows": int(test.unseen_attack.sum()),
        "train_category_counts": train.category.value_counts().to_dict(),
        "test_category_counts": test.category.value_counts().to_dict(),
    }
    (OUT / "dataset_summary.json").write_text(json.dumps(info, indent=2))

    # SVM with RBF kernel scales badly; train it on a stratified 25k sample (documented limitation)
    svm_idx = train.groupby("is_attack", group_keys=False).sample(frac=25000 / len(train), random_state=SEED).index

    models = build_models()
    rows, fitted, probas = [], {}, {}
    for name, model in models.items():
        Xf, yf = (X_tr.loc[svm_idx], y_tr.loc[svm_idx]) if name.startswith("SVM") else (X_tr, y_tr)
        t0 = time.perf_counter(); model.fit(Xf, yf); train_s = time.perf_counter() - t0
        t0 = time.perf_counter(); proba = model.predict_proba(X_te)[:, 1]; infer_s = time.perf_counter() - t0
        pred = (proba >= 0.5).astype(int)
        m = binary_metrics(y_te, pred, proba)
        m.update(model=name, train_rows=len(Xf), train_seconds=train_s,
                 records_per_second=len(X_te) / infer_s)
        rows.append(m); fitted[name] = model; probas[name] = proba
        print(f"{name}: F1={m['f1']:.3f} recall={m['recall']:.3f} FPR={m['false_positive_rate']:.3f} ({train_s:.0f}s)")

    # Soft-voting ensemble of the three full-data models
    ens_proba = np.mean([probas[n] for n in ENSEMBLE], axis=0)  # same as ensemble_score(), without re-predicting
    ens_pred = (ens_proba >= 0.5).astype(int)
    m = binary_metrics(y_te, ens_pred, ens_proba)
    m.update(model="Ensemble (RF+GB+MLP)", train_rows=len(X_tr),
             train_seconds=sum(r["train_seconds"] for r in rows if r["model"] in ENSEMBLE),
             records_per_second=np.nan)
    rows.append(m); probas["Ensemble (RF+GB+MLP)"] = ens_proba
    res = pd.DataFrame(rows).set_index("model")
    res.to_csv(OUT / "metrics_binary.csv", float_format="%.6f")
    print(res[["accuracy", "precision", "recall", "f1", "false_positive_rate", "roc_auc"]].round(4))

    # 'Lab' numbers: 5-fold CV inside the training distribution (RF and GB only, to keep runtime sane)
    cv_rows = []
    skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
    for name in ("Random Forest", "Gradient Boosting"):
        cv = cross_validate(build_models()[name], X_tr, y_tr, cv=skf,
                            scoring=["accuracy", "precision", "recall", "f1"], n_jobs=1)
        cv_rows.append({"model": name, **{k.replace("test_", ""): v.mean() for k, v in cv.items() if k.startswith("test_")}})
    pd.DataFrame(cv_rows).set_index("model").to_csv(OUT / "cv_binary.csv", float_format="%.6f")
    print(pd.DataFrame(cv_rows))

    # Recall per attack family, split into attack types seen in training vs unseen (novel)
    rec = []
    for name, proba in probas.items():
        pred = proba >= 0.5
        for cat in ["DoS", "Probe", "R2L", "U2R"]:
            for seen_flag, label in ((0, "seen"), (1, "unseen")):
                mask = (test.category == cat) & (test.unseen_attack == seen_flag)
                if mask.sum():
                    rec.append({"model": name, "category": cat, "attack_types": label,
                                "rows": int(mask.sum()), "recall": pred[mask.values].mean()})
        for seen_flag, label in ((0, "seen"), (1, "unseen")):
            mask = (test.is_attack == 1) & (test.unseen_attack == seen_flag)
            rec.append({"model": name, "category": "ALL", "attack_types": label,
                        "rows": int(mask.sum()), "recall": pred[mask.values].mean()})
    pd.DataFrame(rec).to_csv(OUT / "per_category_recall.csv", index=False, float_format="%.6f")

    # Multiclass (Normal/DoS/Probe/R2L/U2R) with Random Forest
    mc = build_models()["Random Forest"]
    mc.set_params(clf__class_weight="balanced_subsample")
    mc.fit(X_tr, train.category)
    mc_pred = mc.predict(X_te)
    report = classification_report(test.category, mc_pred, digits=3, zero_division=0)
    (OUT / "multiclass_report.txt").write_text(report)
    print(report)
    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay.from_predictions(test.category, mc_pred, ax=ax, cmap="Blues", colorbar=False)
    ax.set_title("Random Forest, 5-class, KDDTest+")
    fig.tight_layout(); fig.savefig(OUT / "confusion_multiclass_rf.png", dpi=150); plt.close(fig)

    # Binary confusion matrix for RF, ROC for all
    fig, ax = plt.subplots(figsize=(4.5, 4))
    ConfusionMatrixDisplay.from_predictions(y_te, probas["Random Forest"] >= 0.5, display_labels=["Normal", "Attack"],
                                            ax=ax, cmap="Blues", colorbar=False)
    ax.set_title("Random Forest, binary, KDDTest+")
    fig.tight_layout(); fig.savefig(OUT / "confusion_binary_rf.png", dpi=150); plt.close(fig)
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    for name, proba in probas.items():
        RocCurveDisplay.from_predictions(y_te, proba, name=name, ax=ax)
    ax.set_title("ROC curves, KDDTest+")
    fig.tight_layout(); fig.savefig(OUT / "roc.png", dpi=150); plt.close(fig)

    # Feature importance (impurity-based, Random Forest)
    rf = fitted["Random Forest"]
    names = rf.named_steps["prep"].get_feature_names_out()
    fi = pd.Series(rf.named_steps["clf"].feature_importances_, index=names).sort_values(ascending=False)
    fi.head(20).to_csv(OUT / "feature_importance.csv", header=["importance"], float_format="%.6f")

    joblib.dump({"models": fitted, "multiclass_rf": mc}, OUT / "models.joblib", compress=3)


if __name__ == "__main__":
    main()
