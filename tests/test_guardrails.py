import numpy as np
import pytest

from guardrails import fpr, psi


def test_psi_identical_distribution_is_near_zero():
    x = np.random.default_rng(0).normal(size=5000)
    assert psi(x, x) == pytest.approx(0.0, abs=1e-9)


def test_psi_flags_a_large_shift():
    rng = np.random.default_rng(0)
    assert psi(rng.normal(size=5000), rng.normal(loc=2.0, size=5000)) > 0.25


def test_psi_constant_feature_returns_zero():
    assert psi(np.zeros(100), np.ones(100)) == 0.0


def test_fpr():
    y = np.array([0, 0, 0, 0, 1, 1])
    pred = np.array([1, 0, 0, 0, 1, 0])
    assert fpr(y, pred) == pytest.approx(0.25)
