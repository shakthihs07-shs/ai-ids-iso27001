"""Live service: decision bands, the scoring API, and the WebSocket stream.

Runs on a small synthetic detector built with the real training code (app.train.fit_detector),
so CI needs no dataset download.
"""
import importlib
import json

import joblib
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.detector import ALERT, ALLOW, REVIEW, decide
from app.train import fit_detector

FEATURES = ["f0", "f1", "f2", "f3"]


def test_decision_bands():
    sup = [0.95, 0.7, 0.69, 0.2, 0.19, 0.05, 0.05]
    anomaly = [False, False, False, False, False, True, False]
    assert decide(sup, anomaly).tolist() == [ALERT, ALERT, REVIEW, REVIEW, ALLOW, REVIEW, ALLOW]


def flows(n, attack, rng):
    return pd.DataFrame(rng.normal(6 if attack else 0, 1, (n, len(FEATURES))), columns=FEATURES)


@pytest.fixture(scope="module")
def client(tmp_path_factory, monkeypatch_module):
    rng = np.random.default_rng(0)
    train = pd.concat([flows(400, False, rng).assign(Label="BENIGN"), flows(100, True, rng).assign(Label="DoS Hulk")])
    art = fit_detector(train.reset_index(drop=True), FEATURES)
    path = tmp_path_factory.mktemp("artifacts")
    joblib.dump({**art, "card": {"novel_types": ["Portscan"]}}, path / "detector.joblib")
    replay = pd.concat([flows(30, False, rng).assign(Label="BENIGN", scenario="known", technique=""),
                        flows(10, True, rng).assign(Label="DoS Hulk", scenario="known", technique="T1499.002"),
                        flows(20, True, rng).assign(Label="Portscan", scenario="recon-ddos", technique="T1046")])
    replay = replay.assign(Timestamp=[f"2017-07-04 09:{i // 60:02d}:{i % 60:02d}" for i in range(len(replay))],
                           **{"Src IP": "10.0.0.1", "Src Port": 50000, "Dst IP": "10.0.0.2", "Dst Port": 80, "Protocol": 6})
    replay.to_csv(path / "replay.csv.gz", index=False)
    monkeypatch_module.setenv("IDS_ARTIFACTS", str(path))
    main = importlib.reload(importlib.import_module("app.main"))
    with TestClient(main.app) as c:
        yield c


@pytest.fixture(scope="module")
def monkeypatch_module():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


def test_health_and_model_card(client):
    assert client.get("/api/health").json()["status"] == "ok"
    card = client.get("/api/model").json()
    assert card["feature_names"] == FEATURES
    assert card["thresholds"]["alert"] == 0.7 and card["thresholds"]["review"] == 0.2
    assert set(card["scenarios"]) == {"mixed", "known", "recon-ddos"}


def test_score_separates_attacks_from_benign(client):
    rng = np.random.default_rng(1)
    body = {"flows": flows(5, True, rng).to_dict("records") + flows(5, False, rng).to_dict("records")}
    res = client.post("/api/score", json=body).json()["results"]
    assert [r["decision"] for r in res[:5]] == [ALERT] * 5
    assert all(r["decision"] != ALERT for r in res[5:])
    assert all(0 <= r["supervised"] <= 1 for r in res)


@pytest.mark.parametrize("body, why", [
    ({"flows": [{"f0": 1.0, "f1": 1.0}]}, "missing features"),
    ({"flows": []}, "empty batch"),
    ({"flows": [{f: 0.0 for f in FEATURES}] * 1001}, "batch over 1,000"),
    ({"flows": [{"f0": "x", "f1": 0, "f2": 0, "f3": 0}]}, "non-numeric value"),
])
def test_score_rejects_bad_input(client, body, why):
    r = client.post("/api/score", json=body)
    assert r.status_code == 422, why
    if why == "missing features":
        assert r.json()["detail"]["missing"] == ["f2", "f3"]


def test_stream_sends_scored_flows_and_follows_controls(client):
    with client.websocket_connect("/ws/stream") as ws:
        first = ws.receive_json()
        assert first["type"] == "flows" and first["scenario"] == "mixed" and len(first["flows"]) == 10  # 20/s default
        assert {"ts", "src", "dst", "dport", "label", "technique", "supervised", "anomaly", "decision"} <= set(first["flows"][0])
        ws.send_text("not json")  # ignored, the stream keeps going
        ws.send_text(json.dumps({"scenario": "recon-ddos", "speed": 100}))
        for _ in range(3):  # let the controls take effect
            msg = ws.receive_json()
        assert msg["scenario"] == "recon-ddos" and len(msg["flows"]) == 50
        assert {f["label"] for f in msg["flows"]} == {"Portscan"}
        ws.send_text(json.dumps({"scenario": "no-such-scenario", "speed": 10**9}))
        for _ in range(3):
            msg = ws.receive_json()
        assert msg["scenario"] == "recon-ddos" and len(msg["flows"]) == 250  # speed clipped to 500/s


def test_onnx_export_matches_detector(tmp_path):
    """The in-browser console (live/) scores with ONNX exports of the detector; they must decide like it does."""
    import onnx
    from app.detector import Detector
    from app.export_web import export_models, onnx_decisions

    rng = np.random.default_rng(2)
    train = pd.concat([flows(400, False, rng).assign(Label="BENIGN"), flows(100, True, rng).assign(Label="DoS Hulk")])
    art = fit_detector(train.reset_index(drop=True), FEATURES)
    joblib.dump({**art, "card": {}}, tmp_path / "detector.joblib")
    sup, anomaly, threshold = export_models(art)
    test = pd.concat([flows(300, False, rng), flows(100, True, rng), pd.DataFrame(rng.normal(0, 4, (200, 4)), columns=FEATURES)])
    py, ox = Detector(tmp_path / "detector.joblib").score(test), onnx_decisions(sup, anomaly, threshold, test.values)
    assert (py.decision.values == ox.decision.values).all()
    assert (py.anomaly.values == ox.anomaly.values).all() and py.anomaly.any() and not py.anomaly.all()
    for model in (sup, anomaly):  # onnxruntime-web 1.20 reads ONNX format versions up to 10
        assert onnx.load_from_string(model).ir_version <= 10
    assert len(onnx.load_from_string(anomaly).graph.node) == 2  # one tree operator, so the browser loads it fast
