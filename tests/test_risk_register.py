"""The risk register must stay consistent with its own method and with the committed CSV."""
import re

import pandas as pd
import pytest

import build_risk_register as brr
from conftest import ROOT

# ISO/IEC 27001:2022 Annex A: 5.1-5.37, 6.1-6.8, 7.1-7.14, 8.1-8.34
ANNEX_A = {5: 37, 6: 8, 7: 14, 8: 34}


@pytest.mark.parametrize("score,rating", [(1, "Low"), (4, "Low"), (5, "Medium"), (9, "Medium"),
                                          (10, "High"), (15, "High"), (16, "Critical"), (25, "Critical")])
def test_band_boundaries(score, rating):
    assert brr.band(score) == rating


def test_risks_are_well_formed():
    ids = [r[0] for r in brr.RISKS]
    assert ids == [f"R{i:02d}" for i in range(1, len(ids) + 1)]
    for r in brr.RISKS:
        L, I, rL, rI = r[6], r[7], r[11], r[12]
        assert all(1 <= v <= 5 for v in (L, I, rL, rI)), r[0]
        assert rL * rI <= L * I, f"{r[0]}: residual exceeds inherent"


def test_annex_a_references_exist():
    for r in brr.RISKS:
        for ref in r[10].split(","):
            m = re.fullmatch(r"\s*([5-8])\.(\d+)\s*", ref)
            assert m, f"{r[0]}: bad control '{ref}'"
            theme, num = int(m[1]), int(m[2])
            assert 1 <= num <= ANNEX_A[theme], f"{r[0]}: {ref} is not an Annex A control"


def test_committed_register_matches_generator(tmp_path, monkeypatch):
    monkeypatch.setattr(brr, "ROOT", tmp_path)
    brr.main()
    fresh = pd.read_csv(tmp_path / "risk_register.csv")
    committed = pd.read_csv(ROOT / "risk_register.csv")
    pd.testing.assert_frame_equal(fresh, committed)
