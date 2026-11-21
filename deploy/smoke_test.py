"""Smoke test a running Live IDS service: model card, scoring API and the live stream.

    python deploy/smoke_test.py http://localhost:7860

Exits non-zero on the first failed check. Needs only the standard library plus `websockets`.
"""
import json
import sys
import urllib.error
import urllib.request

from websockets.sync.client import connect

base = sys.argv[1].rstrip("/")


def get(path):
    with urllib.request.urlopen(base + path, timeout=30) as r:
        return json.load(r)


def post(path, body):
    req = urllib.request.Request(base + path, json.dumps(body).encode(), {"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


card = get("/api/model")
assert card["detected_known"] > 0.99, f"known-attack detection too low: {card['detected_known']}"
assert card["detected_novel"] > 0.5, f"novel-attack detection too low: {card['detected_novel']}"
assert card["benign_flagged"] < 0.07, f"benign flag rate too high: {card['benign_flagged']}"
assert len(card["feature_names"]) == 82 and set(card["scenarios"]) == {"mixed", "known", "recon-ddos", "web-infiltration"}
print(f"model card: known {card['detected_known']:.4f}, novel {card['detected_novel']:.4f}, benign flagged {card['benign_flagged']:.4f}")

status, res = post("/api/score", {"flows": [{f: 0.0 for f in card["feature_names"]}]})
assert status == 200 and res["results"][0]["decision"] in {"ALERT", "REVIEW", "ALLOW"}, res
status, res = post("/api/score", {"flows": [{"Protocol": 6.0}]})
assert status == 422 and len(res["detail"]["missing"]) == 81, res
print("score API: ok")

with connect(base.replace("http", "ws", 1) + "/ws/stream", open_timeout=30) as ws:
    first = json.loads(ws.recv(timeout=10))
    assert first["type"] == "flows" and len(first["flows"]) == 10, first
    ws.send(json.dumps({"scenario": "recon-ddos", "speed": 100}))
    for _ in range(4):
        msg = json.loads(ws.recv(timeout=10))
    assert msg["scenario"] == "recon-ddos" and len(msg["flows"]) == 50, {k: msg[k] for k in ("scenario", "latency_ms")}
    print(f"stream: ok, {len(msg['flows'])} flows per half second, {msg['latency_ms']} ms to score a batch")
print("all checks passed")
