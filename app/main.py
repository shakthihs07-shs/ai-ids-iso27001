"""Live IDS service: scores network flows in real time with the hybrid detector.

    uvicorn app.main:app --port 7860

  GET  /                live SOC dashboard
  GET  /api/health      liveness
  GET  /api/model       model card: how the detector was trained and how it scored on the test split
  POST /api/score       score up to 1,000 flows (CICFlowMeter features) in one request
  WS   /ws/stream       live stream: replayed CIC-IDS2017 test flows, scored as they arrive.
                        Send {"scenario": ..., "speed": flows per second, "paused": bool} to steer it.
"""
import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.detector import ALERT_AT, REVIEW_AT, ROOT, Detector

ART = Path(os.environ.get("IDS_ARTIFACTS", ROOT / "app" / "artifacts"))
STATIC = ROOT / "app" / "static"
MAX_BATCH, MAX_STREAMS, TICK = 1000, 20, 0.5  # MAX_STREAMS: a free 2-CPU host keeps up with ~20 viewers
SPEEDS = (1, 500)  # flows per second a stream may ask for
DISPLAY = {"Timestamp": "ts", "Src IP": "src", "Src Port": "sport", "Dst IP": "dst", "Dst Port": "dport",
           "Protocol": "proto", "Label": "label", "technique": "technique"}

state = {"streams": 0}


@asynccontextmanager
async def lifespan(app):
    state["detector"] = Detector(ART / "detector.joblib")
    replay = pd.read_csv(ART / "replay.csv.gz", low_memory=False)
    replay["technique"] = replay["technique"].fillna("")
    state["scenarios"] = {"mixed": replay.sort_values("Timestamp", kind="stable").reset_index(drop=True),
                          **{k: g.reset_index(drop=True) for k, g in replay.groupby("scenario", sort=False)}}
    yield


app = FastAPI(title="Live IDS: hybrid ML intrusion detection", lifespan=lifespan)


class ScoreRequest(BaseModel):
    flows: list[dict[str, float]] = Field(min_length=1, max_length=MAX_BATCH,
                                          description="Flows as {feature name: value}; see GET /api/model for the names")


@app.get("/api/health")
def health():
    return {"status": "ok", "streams": state["streams"]}


@app.get("/api/model")
def model():
    det = state["detector"]
    return {**det.card, "thresholds": {"alert": ALERT_AT, "review": REVIEW_AT, "anomaly_cut": det.cut},
            "feature_names": det.features, "scenarios": {k: len(v) for k, v in state["scenarios"].items()}}


@app.post("/api/score")
def score(req: ScoreRequest):
    det = state["detector"]
    flows = pd.DataFrame(req.flows)
    missing = [f for f in det.features if f not in flows.columns]
    if missing:
        raise HTTPException(422, {"error": "missing features", "missing": missing})
    t0 = time.perf_counter()
    res = det.score(flows)
    return {"latency_ms": round(1000 * (time.perf_counter() - t0), 2), "results": _records(res)}


def _records(res: pd.DataFrame, display: pd.DataFrame | None = None) -> list[dict]:
    out = pd.DataFrame({"supervised": res.supervised.round(4), "anomaly_score": res.anomaly_score.round(4),
                        "anomaly": res.anomaly, "decision": res.decision})
    if display is not None:
        out = pd.concat([display.rename(columns=DISPLAY).reset_index(drop=True), out.reset_index(drop=True)], axis=1)
    return json.loads(out.to_json(orient="records"))


@app.websocket("/ws/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    if state["streams"] >= MAX_STREAMS:
        await ws.close(code=1013, reason="too many viewers, try again shortly")
        return
    state["streams"] += 1
    ctl = {"scenario": "mixed", "speed": 20, "paused": False, "pos": 0}

    async def listen():
        while True:
            try:
                msg = json.loads(await ws.receive_text())
            except ValueError:
                continue  # ignore malformed control messages
            if not isinstance(msg, dict):
                continue
            if msg.get("scenario") in state["scenarios"]:
                ctl.update(scenario=msg["scenario"], pos=0)
            if isinstance(msg.get("speed"), (int, float)) and not isinstance(msg["speed"], bool):
                ctl["speed"] = int(np.clip(msg["speed"], *SPEEDS))
            if isinstance(msg.get("paused"), bool):
                ctl["paused"] = msg["paused"]

    listener = asyncio.create_task(listen())
    try:
        det = state["detector"]
        while not listener.done():
            await asyncio.sleep(TICK)
            if ctl["paused"]:
                continue
            df = state["scenarios"][ctl["scenario"]]
            n = max(1, round(ctl["speed"] * TICK))
            idx = np.arange(ctl["pos"], ctl["pos"] + n) % len(df)  # loop the replay
            ctl["pos"] = int((ctl["pos"] + n) % len(df))
            batch = df.iloc[idx]
            t0 = time.perf_counter()
            res = await asyncio.to_thread(det.score, batch)
            latency = round(1000 * (time.perf_counter() - t0), 2)
            await ws.send_json({"type": "flows", "scenario": ctl["scenario"], "latency_ms": latency,
                                "flows": _records(res, batch[list(DISPLAY)])})
        listener.result()  # re-raise why the listener stopped
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        listener.cancel()
        state["streams"] -= 1


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
