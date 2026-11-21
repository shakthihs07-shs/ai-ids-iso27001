"""The Statement of Applicability (grc/soa.csv) is complete, its evidence exists, and docs/06 and soa.xlsx agree with it."""
import re

import pandas as pd
import pytest

import build_soa
from conftest import ROOT

SOA = build_soa.load()
ANNEX_A = [f"{theme}.{n}" for theme, count in (("5", 37), ("6", 8), ("7", 14), ("8", 34)) for n in range(1, count + 1)]


def test_all_93_annex_a_controls_in_order():
    assert SOA.Control.tolist() == ANNEX_A


@pytest.mark.parametrize("row", SOA.to_dict("records"), ids=SOA.Control.tolist())
def test_each_control_is_justified_and_evidenced(row):
    assert row["Status"] in build_soa.STATUSES
    assert (row["Status"] == "Not applicable") == (row["Applicable"] == "No")
    assert row["How it is met / justification"]
    evidence = [p.strip() for p in row["Evidence (repository files)"].split(";") if p.strip()]
    for path in evidence:
        assert (ROOT / path).is_file(), f"{row['Control']}: evidence {path} does not exist"
    if row["Status"] in ("Implemented", "Inherited"):
        assert evidence, f"{row['Control']} is {row['Status']} but names no evidence"
    if row["Status"] in ("Partial", "Planned"):
        assert row["Gap / action"], f"{row['Control']} is {row['Status']} but states no gap or action"


def test_pack_summary_matches_the_soa():
    doc = (ROOT / "docs" / "06_grc_evidence_pack.md").read_text(encoding="utf-8")
    for theme, counts in build_soa.summary(SOA).iterrows():
        name = re.escape(theme if theme != "All" else "**All**")
        cells = r"\s*\|\s*".join(rf"\**{n}\**" for n in counts)
        assert re.search(rf"\|\s*{name}\s*\|\s*{cells}\s*\|", doc), f"docs/06 summary row for {theme} is out of date"


def test_excel_matches_the_csv():
    xlsx = pd.read_excel(ROOT / "grc" / "soa.xlsx", sheet_name=None, dtype=str)
    stale = "grc/soa.xlsx is stale: run python src/build_soa.py"
    assert xlsx["Statement of Applicability"][SOA.columns].fillna("").equals(SOA), stale
    risks = build_soa.load_risks().astype(str)
    assert xlsx["Live risk register"].fillna("").equals(risks), stale


# ---- live-service risk register (grc/risk_register_live.csv) ----
RISKS = build_soa.load_risks()


def test_live_risks_are_well_formed():
    assert RISKS["Risk ID"].tolist() == [f"LR{i:02d}" for i in range(1, len(RISKS) + 1)]
    for col in ("Likelihood", "Impact", "Residual likelihood", "Residual impact"):
        assert RISKS[col].between(1, 5).all(), col
    assert (RISKS["Residual score"] <= RISKS["Inherent score"]).all()


@pytest.mark.parametrize("risk", RISKS.to_dict("records"), ids=RISKS["Risk ID"].tolist())
def test_live_risk_is_treated_by_applicable_controls_and_decided(risk):
    applicable = set(SOA.Control[SOA.Applicable == "Yes"])
    named = build_soa.controls(risk["Annex A controls"])
    assert named, f"{risk['Risk ID']} names no controls"
    assert set(named) <= applicable, f"{risk['Risk ID']}: not applicable or unknown: {set(named) - applicable}"
    above = risk["Residual score"] > build_soa.ACCEPTANCE
    assert risk["Decision"] == ("Treat" if above else "Accept"), risk["Risk ID"]
    if above:
        assert risk["Open treatment"], f"{risk['Risk ID']} is above acceptance but has no open treatment"


def test_risk_assessment_document_matches_the_register():
    doc = (ROOT / "docs" / "08_live_service_risk_assessment.md").read_text(encoding="utf-8")
    for r in RISKS.to_dict("records"):
        row = (rf"\|\s*{r['Risk ID']}\s*\|[^\n]*\|\s*\**{r['Inherent score']} {r['Inherent rating']}\**\s*\|"
               rf"[^\n]*\|\s*\**{r['Residual score']} {r['Residual rating']}\**\s*\|")
        assert re.search(row, doc), f"docs/08 row for {r['Risk ID']} is out of date"
