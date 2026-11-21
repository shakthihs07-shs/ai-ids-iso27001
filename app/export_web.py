"""Export the live console for in-browser scoring, served from GitHub Pages at /live/.

    python -m app.train && python -m app.export_web

Writes live/: index.html (the same console as app/static, with the browser engine), the two models
as ONNX, card.json, and the replay flows. The flow features go through signed_log in JavaScript
(browser-engine.js), then the ONNX models: Gradient Boosting, and the scaler + Isolation Forest.
The export stops if the ONNX models disagree with the Python detector on the replay flows.
"""
import json
import shutil

import joblib
import numpy as np
import onnx
import onnxruntime as ort
import pandas as pd
from skl2onnx import convert_sklearn
from skl2onnx.common import tree_ensemble
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble._iforest import _average_path_length

from app.detector import ALERT_AT, REVIEW_AT, ROOT, Detector, decide
from cicids2017 import signed_log

ART, OUT, STATIC = ROOT / "app" / "artifacts", ROOT / "live", ROOT / "app" / "static"
OPSET = {"": 17, "ai.onnx.ml": 3}  # ai.onnx.ml 3 keeps the tree operators loadable by onnxruntime-web
ORT_WEB = "1.20.1"

# shortcut: skl2onnx 1.20 passes Python bools for HistGradientBoosting's missing-value flag, which onnx>=1.18
# rejects in an int attribute; cast them. Drop this once skl2onnx casts it itself.
_add_node = tree_ensemble.add_node
tree_ensemble.add_node = lambda *a, nodes_missing_value_tracks_true=0, **k: _add_node(
    *a, nodes_missing_value_tracks_true=int(nodes_missing_value_tracks_true), **k)


def to_onnx(model, n_features, options=None):
    return convert_sklearn(model, initial_types=[("x", FloatTensorType([None, n_features]))],
                           target_opset=OPSET, options=options).SerializeToString()


def isolation_forest_onnx(scaler, iso, n_features: int) -> bytes:
    """Scaler + Isolation Forest as two ONNX nodes whose output is the summed path length over all trees.

    skl2onnx's own converter emits ~10,000 nodes (a small subgraph per tree), which onnxruntime-web takes
    15 s to load. Here every leaf carries the path length scikit-learn assigns it (depth + average path
    length of the samples left in the leaf), so a single TreeEnsembleRegressor sums them."""
    a = {k: [] for k in ("nodes_treeids", "nodes_nodeids", "nodes_featureids", "nodes_values", "nodes_modes",
                         "nodes_truenodeids", "nodes_falsenodeids", "nodes_missing_value_tracks_true",
                         "target_treeids", "target_nodeids", "target_ids", "target_weights")}
    trees = zip(iso.estimators_, iso.estimators_features_, iso._decision_path_lengths, iso._average_path_length_per_tree)
    for t, (est, feats, depth, apl) in enumerate(trees):
        tree = est.tree_
        for i in range(tree.node_count):
            leaf = tree.children_left[i] == -1
            a["nodes_treeids"].append(t); a["nodes_nodeids"].append(i)
            a["nodes_featureids"].append(0 if leaf else int(feats[tree.feature[i]]))
            a["nodes_values"].append(0.0 if leaf else float(tree.threshold[i]))
            a["nodes_modes"].append("LEAF" if leaf else "BRANCH_LEQ")
            a["nodes_truenodeids"].append(0 if leaf else int(tree.children_left[i]))
            a["nodes_falsenodeids"].append(0 if leaf else int(tree.children_right[i]))
            a["nodes_missing_value_tracks_true"].append(0)
            if leaf:
                a["target_treeids"].append(t); a["target_nodeids"].append(i); a["target_ids"].append(0)
                a["target_weights"].append(float(depth[i] + apl[i] - 1.0))
    nodes = [onnx.helper.make_node("Scaler", ["x"], ["z"], domain="ai.onnx.ml",
                                   offset=scaler.mean_.tolist(), scale=(1 / scaler.scale_).tolist()),
             onnx.helper.make_node("TreeEnsembleRegressor", ["z"], ["scores"], domain="ai.onnx.ml", n_targets=1,
                                   aggregate_function="SUM", post_transform="NONE", **a)]
    graph = onnx.helper.make_graph(nodes, "isolation_forest",
                                   [onnx.helper.make_tensor_value_info("x", onnx.TensorProto.FLOAT, [None, n_features])],
                                   [onnx.helper.make_tensor_value_info("scores", onnx.TensorProto.FLOAT, [None, 1])])
    model = onnx.helper.make_model(graph, opset_imports=[onnx.helper.make_opsetid(d, v) for d, v in OPSET.items()],
                                   ir_version=8)  # the newest onnx stamps a format onnxruntime-web 1.20 cannot read
    onnx.checker.check_model(model)
    return model.SerializeToString()


def export_models(art: dict) -> tuple[bytes, bytes, float]:
    """ONNX bytes for the supervised model and the anomaly layer, and the anomaly threshold on the anomaly
    model's output. Both expect signed_log(features) as float32; that preprocessing runs outside ONNX."""
    n = len(art["features"])
    clf = art["supervised"].named_steps["clf"]
    sup = to_onnx(clf, n, {id(clf): {"zipmap": False}})
    scaler, iso = art["iso"].named_steps["prep"].named_steps["scale"], art["iso"].named_steps["clf"]
    anomaly = isolation_forest_onnx(scaler, iso, n)
    # scikit-learn: score_samples = -2 ** (-path_sum / (n_trees * c)), c = average path length of max_samples.
    # The detector flags -score_samples > cut, which is path_sum < -n_trees * c * log2(cut).
    c = float(_average_path_length([iso.max_samples_])[0])
    return sup, anomaly, float(-len(iso.estimators_) * c * np.log2(art["cut"]))


def onnx_decisions(sup: bytes, anomaly: bytes, threshold: float, X: np.ndarray) -> pd.DataFrame:
    x = signed_log(X).astype(np.float32)
    proba = ort.InferenceSession(sup).run(["probabilities"], {"x": x})[0][:, 1]
    scores = ort.InferenceSession(anomaly).run(["scores"], {"x": x})[0].ravel()
    return pd.DataFrame({"supervised": proba, "anomaly": scores < threshold, "decision": decide(proba, scores < threshold)})


def main():
    art = joblib.load(ART / "detector.joblib")
    det = Detector(ART / "detector.joblib")
    sup, anomaly, threshold = export_models(art)
    replay = pd.read_csv(ART / "replay.csv.gz", low_memory=False)

    # Parity: the browser must reach the same decisions as the Python detector on every replay flow
    py, ox = det.score(replay), onnx_decisions(sup, anomaly, threshold, replay[det.features].values)
    parity = {"flows": len(replay), "decisions_equal": float((py.decision.values == ox.decision.values).mean()),
              "anomaly_flags_equal": float((py.anomaly.values == ox.anomaly.values).mean()),
              "max_supervised_diff": float(np.abs(py.supervised.values - ox.supervised.values).max())}
    print(json.dumps(parity))
    assert parity["decisions_equal"] > 0.999 and parity["anomaly_flags_equal"] > 0.999, parity

    OUT.joinpath("model").mkdir(parents=True, exist_ok=True)
    OUT.joinpath("model", "supervised.onnx").write_bytes(sup)
    OUT.joinpath("model", "anomaly.onnx").write_bytes(anomaly)
    card = {**det.card, "features_order": det.features, "anomaly_threshold": threshold,
            "thresholds": {"alert": ALERT_AT, "review": REVIEW_AT}, "onnx_parity": parity, "onnxruntime_web": ORT_WEB}
    OUT.joinpath("model", "card.json").write_text(json.dumps(card, indent=1))
    shutil.copy(ART / "replay.csv.gz", OUT / "replay.csv.gz")

    page = (STATIC / "index.html").read_text(encoding="utf-8")
    engine = (f'<script src="https://cdn.jsdelivr.net/npm/onnxruntime-web@{ORT_WEB}/dist/ort.min.js"></script>\n'
              f'<script>window.ORT_WASM = "https://cdn.jsdelivr.net/npm/onnxruntime-web@{ORT_WEB}/dist/";</script>\n'
              '<script src="browser-engine.js"></script>\n<script>')
    assert page.count("<script>") == 1
    OUT.joinpath("index.html").write_text(page.replace("<script>", engine), encoding="utf-8")
    shutil.copy(STATIC / "browser-engine.js", OUT / "browser-engine.js")
    print(f"wrote {OUT}: {sum(f.stat().st_size for f in OUT.rglob('*') if f.is_file()) / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
