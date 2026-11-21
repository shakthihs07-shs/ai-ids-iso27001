"""Preprocessing and label mapping. Synthetic data only, no dataset download needed."""
import numpy as np
import pandas as pd
import pytest

from common import CATEGORY, CATEGORICAL, COLUMNS, HEAVY_TAILED, DATA, _log_heavy, feature_cols, load, make_preprocessor


def synthetic_frame(n=50, seed=0):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({c: rng.integers(0, 1000, n) for c in feature_cols()})
    df["protocol_type"] = rng.choice(["tcp", "udp", "icmp"], n)
    df["service"] = rng.choice(["http", "ftp", "private"], n)
    df["flag"] = rng.choice(["SF", "S0", "REJ"], n)
    return df


def test_category_values_are_the_five_classes():
    assert set(CATEGORY.values()) == {"Normal", "DoS", "Probe", "R2L", "U2R"}


def test_feature_columns_exclude_target():
    cols = feature_cols()
    assert len(cols) == 41
    assert "label" not in cols and "difficulty" not in cols
    assert set(CATEGORICAL) <= set(cols) and set(HEAVY_TAILED) <= set(cols)


def test_log_transform_only_touches_selected_columns():
    X = np.array([[0.0, 9.0], [np.e - 1, 99.0]])
    out = _log_heavy(X, cols_idx=[0])
    assert out[:, 0] == pytest.approx([0.0, 1.0])
    assert out[:, 1].tolist() == [9.0, 99.0]
    assert X[1, 0] == pytest.approx(np.e - 1)  # input not mutated


@pytest.mark.parametrize("scale", [True, False])
def test_preprocessor_output_is_finite(scale):
    train, test = synthetic_frame(seed=1), synthetic_frame(seed=2)
    test.loc[0, "service"] = "never_seen_service"  # handle_unknown="ignore"
    pre = make_preprocessor(scale=scale).fit(train)
    out = pre.transform(test)
    assert out.shape[0] == len(test)
    assert np.isfinite(out).all()


@pytest.mark.skipif(not (DATA / "KDDTrain+.txt").exists(), reason="dataset not downloaded (bash data/download.sh)")
def test_dataset_matches_documented_shape():
    train, test, unseen = load()
    assert (len(train), len(test)) == (125973, 22544)
    assert len(unseen) == 17
    assert train["category"].notna().all() and test["category"].notna().all()
