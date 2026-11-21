"""CIC-IDS2017 run: preprocessing edge cases, and the numbers the docs quote must match results/cicids2017/."""
import json
import re

import numpy as np
import pandas as pd

from cicids2017 import signed_log
from conftest import ROOT

RES = ROOT / "results" / "cicids2017"
ENS = "Ensemble (RF+GB+MLP)"


def test_signed_log_handles_nan_inf_and_negatives():
    out = signed_log([[np.nan, np.inf, -np.inf, 0.0, -9.0, 9.0]])
    assert np.isfinite(out).all()
    assert out[0, :4].tolist() == [0.0, 0.0, 0.0, 0.0]
    assert out[0, 4] == -out[0, 5] == -np.log1p(9.0)


def pct(x, digits=1):
    return f"{x:.{digits}%}"


def claims():
    hyb = pd.read_csv(RES / "hybrid.csv").set_index("detector")
    rec = pd.read_csv(RES / "per_attack_recall.csv").query("label == 'ALL'").set_index(["model", "attack_types"]).recall
    m = pd.read_csv(RES / "metrics_binary.csv").set_index("model")
    info = json.loads((RES / "dataset_summary.json").read_text())
    iso, both = hyb.loc["Anomaly (Isolation Forest)"], hyb.loc["Hybrid (either layer)"]
    benign = info["test_label_counts"]["BENIGN"]
    thousands = lambda x: f"{int(round(x, -3)):,}"  # the report rounds these to the nearest thousand
    return [
        pct(rec[ENS, "seen"], 2), pct(rec[ENS, "unseen"]), pct(both.recall_unseen_attacks), pct(both.false_positive_rate),
        pct(both.recall_seen_attacks, 2), pct(both.f1), pct(m.loc[ENS, "f1"]),
        pct(rec["Random Forest", "seen"], 2), pct(rec["Random Forest", "unseen"]), pct(m.loc["Random Forest", "f1"]),
        pct(iso.recall_seen_attacks), pct(iso.recall_unseen_attacks), pct(iso.false_positive_rate), pct(iso.f1),
        f"{m.loc['Neural Net (MLP)', 'roc_auc']:.2f}", pct(info["train_attack_share"]), pct(info["test_attack_share"]),
        f"{info['train_rows']:,}", f"{info['test_rows']:,}", f"{info['unseen_attack_rows']:,}",
        thousands(benign), thousands(benign * iso.false_positive_rate),
    ]


def test_report_and_readme_quote_cicids2017_results():
    report = (ROOT / "docs" / "04_findings_report.md").read_text(encoding="utf-8")
    section = report.split("## 7. Repeat on a modern dataset")[1].split("## 8.")[0]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for expected in claims():
        # no digit or point before the match, so "3.2%" is not found inside "73.2%"
        assert re.search(rf"(?<![\d.]){re.escape(expected)}", section), f"report section 7 should quote {expected!r}"
    for expected in claims()[:4]:
        assert re.search(rf"(?<![\d.]){re.escape(expected)}", readme), f"README should quote {expected!r}"
