"""Every measured number the risk register quotes must match the committed results/ files.

The register's evidence column is typed by hand in src/build_risk_register.py. Without this test a
rerun with a newer library can change a result while the register keeps quoting the old one.
Throughput (R13) is left out: it depends on the machine.
"""
import json
import re

import pandas as pd
import pytest

import build_risk_register as brr
from conftest import ROOT

RES = ROOT / "results"
ENS = "Ensemble (RF+GB+MLP)"


# results/ store 6 decimals, so rounding to a 0.1% figure here matches rounding the raw value
def pct(x, digits=1):
    return f"{x:.{digits}%}"


def claims():
    rec = pd.read_csv(RES / "per_category_recall.csv").query("model == @ENS and category == 'ALL'")
    rec = rec.set_index("attack_types").recall
    hybrid = pd.read_csv(RES / "guardrails_hybrid.csv").set_index("detector")
    tech = pd.read_csv(RES / "mitre_by_technique.csv").set_index("technique_id")
    cv = pd.read_csv(RES / "cv_binary.csv").set_index("model")
    metrics = pd.read_csv(RES / "metrics_binary.csv").set_index("model")
    drift = pd.read_csv(RES / "guardrails_drift_psi.csv")
    evasion = pd.read_csv(RES / "guardrails_evasion.csv").evasion_rate
    thr = pd.read_csv(RES / "guardrails_threshold.csv").set_index("threshold")
    hil = json.loads((RES / "guardrails_summary.json").read_text())["human_in_loop"]
    top = drift.iloc[0]
    return [
        ("R01", pct(rec["unseen"])), ("R01", pct(rec["seen"])),
        ("R01", pct(hybrid.loc["Hybrid (either layer)", "recall_unseen_attacks"])),
        ("R02", pct(tech.loc["T1110.001", "recall"], 0)), ("R02", f"{tech.loc['T1110.001', 'test_rows']:,}"),
        ("R02", pct(tech.loc["T1078.001", "recall"], 0)),
        ("R03", "T1190 " + pct(tech.loc["T1190", "recall"], 0)), ("R03", "T1068 " + pct(tech.loc["T1068", "recall"], 0)),
        ("R03", "T1572 " + pct(tech.loc["T1572", "recall"], 0)), ("R03", "T1014 " + pct(tech.loc["T1014", "recall"], 0)),
        ("R04", pct(cv.f1.max())), ("R04", pct(metrics.loc[ENS, "f1"])),
        ("R05", f"{(drift.status == 'moderate shift').sum()} features"), ("R05", f"{top.feature} {top.psi:.3f}"),
        ("R06", f"{evasion.min() * 100:.0f}-{evasion.max() * 100:.0f}%"),
        ("R07", "FPR " + pct(metrics.loc[ENS, "false_positive_rate"])), ("R07", pct(thr.loc[0.05, "false_positive_rate"])),
        ("R07", pct(hil["analyst_review_share"])),
    ]


@pytest.mark.parametrize("risk,expected", claims())
def test_register_quotes_current_results(risk, expected):
    row = next(r for r in brr.RISKS if r[0] == risk)
    text = " ".join(str(v) for v in row)
    # no digit or point before the match, so "0%" is not found inside "10%"
    assert re.search(rf"(?<![\d.]){re.escape(expected)}", text), f"{risk} should quote {expected!r} from results/"
