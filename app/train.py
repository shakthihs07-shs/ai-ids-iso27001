"""Build the live service's artifacts from CIC-IDS2017: the hybrid detector and a replay stream.

    bash data/download_cicids2017.sh && python -m app.train

Uses the research split from src/cicids2017.py, so the replay only contains test flows the
detector never saw: held-out Monday-Wednesday flows (known attack types) and Thursday-Friday
(attack types absent from training).

Writes app/artifacts/detector.joblib and app/artifacts/replay.csv.gz.
"""
import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.pipeline import Pipeline

from app.detector import ALERT, ALLOW, MITRE, REVIEW, ROOT, Detector
from cicids2017 import BENIGN, DROP, make_preprocessor, split
from train_evaluate import SEED

ART = ROOT / "app" / "artifacts"
DISPLAY = ["Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Label"]
# Replay scenarios: which attack types each one streams (benign flows from the same days are mixed in)
SCENARIOS = {
    "known": ["DoS Hulk", "DoS GoldenEye", "DoS Slowloris", "DoS Slowhttptest", "Heartbleed", "FTP-Patator", "SSH-Patator"],
    "recon-ddos": ["Portscan", "DDoS", "Botnet"],
    "web-infiltration": ["Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL Injection",
                         "Infiltration", "Infiltration - Portscan"],
}
PER_TYPE, BENIGN_RATIO, MAX_IDLE = 800, 3, 150


def cap_benign_runs(df: pd.DataFrame, limit: int, seed: int) -> pd.DataFrame:
    """Keep at most `limit` benign flows between two attack flows (a random subset, order kept), so a
    replay viewer never waits minutes for the next attack."""
    attack = (df.Label != BENIGN).values
    run = np.cumsum(attack)  # benign flows between the same two attacks share a run id
    rng = np.random.default_rng(seed)
    keep = attack.copy()
    for r in np.unique(run[~attack]):
        idx = np.flatnonzero(~attack & (run == r))
        keep[rng.choice(idx, min(limit, len(idx)), replace=False)] = True
    return df[keep]


def fit_detector(train: pd.DataFrame, features: list) -> dict:
    """Supervised Gradient Boosting + Isolation Forest on benign flows with a 5% alert budget, as in the research."""
    y = (train.Label != BENIGN).astype(int).values
    supervised = Pipeline([("prep", make_preprocessor(scale=False)),
                           ("clf", HistGradientBoostingClassifier(max_iter=300, random_state=SEED))]).fit(train[features], y)
    benign = train.loc[y == 0, features]
    iso = Pipeline([("prep", make_preprocessor()),
                    ("clf", IsolationForest(n_estimators=300, random_state=SEED, n_jobs=-1))]).fit(benign)
    cut = float(np.quantile(-iso.score_samples(benign), 0.95))
    return {"features": features, "supervised": supervised, "iso": iso, "cut": cut}


def evaluate(det: Detector, test: pd.DataFrame, unseen_types: set) -> dict:
    s = det.score(test)
    attack = (test.Label != BENIGN).values
    unseen = test.Label.isin(unseen_types).values
    flagged = s.decision.values != ALLOW
    share = lambda mask: {d: float((s.decision.values[mask] == d).mean()) for d in (ALERT, REVIEW, ALLOW)}
    return {
        "test_flows": len(test), "test_attacks": int(attack.sum()),
        "benign": share(~attack), "known_attacks": share(attack & ~unseen), "novel_attacks": share(attack & unseen),
        "detected_known": float(flagged[attack & ~unseen].mean()), "detected_novel": float(flagged[attack & unseen].mean()),
        "benign_flagged": float(flagged[~attack].mean()),
        "detected_by_type": {k: float(v) for k, v in pd.Series(flagged[attack]).groupby(test.Label.values[attack]).mean().items()},
    }


def replay_stream(test: pd.DataFrame, features: list) -> pd.DataFrame:
    """Per scenario: up to PER_TYPE flows of each attack type, plus up to BENIGN_RATIO x as many benign flows
    from the same days, in time order, with at most MAX_IDLE benign flows between attacks. A compressed
    replay: real flows, but far more attacks per minute than the lab saw."""
    parts = []
    for name, labels in SCENARIOS.items():
        att = test[test.Label.isin(labels)]
        att = att.sample(frac=1, random_state=SEED).groupby("Label").head(PER_TYPE)
        ben = test[(test.Label == BENIGN) & test.day.isin(att.day.unique())]
        ben = ben.sample(min(len(ben), BENIGN_RATIO * len(att)), random_state=SEED)
        both = pd.concat([att, ben]).sort_values("Timestamp", kind="stable")
        parts.append(cap_benign_runs(both, MAX_IDLE, SEED).assign(scenario=name))
    out = pd.concat(parts, ignore_index=True)
    out["technique"] = out.Label.map(MITRE).fillna("")
    return out[["scenario", "technique"] + DISPLAY + features]


def main():
    t0 = time.time()
    ART.mkdir(parents=True, exist_ok=True)
    train, test = split()
    features = [c for c in train.columns if c not in DROP + ["day", "is_attack", "unseen_attack"]]
    art = fit_detector(train, features)
    path = ART / "detector.joblib"
    joblib.dump({**art, "card": {}}, path, compress=3)
    card = evaluate(Detector(path), test, set(test.Label) - set(train.Label))
    card.update(model="Gradient Boosting + Isolation Forest (5% alert budget on benign training flows)",
                data="CIC-IDS2017, corrected labels (KU Leuven DistriNet, 2023)",
                train_flows=len(train), train_days="70% of Monday-Wednesday", features=len(features),
                novel_types=sorted(set(test.Label) - set(train.Label)), built_in_seconds=None)
    replay = replay_stream(test, features)
    replay.to_csv(ART / "replay.csv.gz", index=False)
    card["replay"] = {k: int(v) for k, v in replay.scenario.value_counts().items()}
    card["built_in_seconds"] = round(time.time() - t0)
    joblib.dump({**art, "card": card}, path, compress=3)
    print(json.dumps(card, indent=2))


if __name__ == "__main__":
    main()
