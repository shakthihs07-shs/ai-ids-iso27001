"""Shadow mode: score real honeypot traffic with the detector, which decides nothing here.

    python score.py <directory of CICFlowMeter CSVs> [tracker database] [model directory]

Reads the flow CSVs the fixed CICFlowMeter wrote for one hour of captured traffic, keeps the connections to the
honeypot's fake services, and scores them with the same ONNX models, transform and decision bands as the live IDS
console (live/browser-engine.js, app/detector.py). Every flow here is unsolicited, so ALLOW means the model would
have let a real attack through. Stored per flow: time, service, port, size, duration, scores and decision. Never
an address: the CSVs carry them, and run-hourly.sh deletes the CSVs right after this runs.
"""
import csv
import ipaddress
import json
import math
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import onnxruntime as ort

SERVICES = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
            6379: "Redis", 8080: "HTTP proxy", 9418: "Git", 27017: "MongoDB"}  # the ports in opencanary.conf
RENAME = {"Total Connection Flow Time": "Total TCP Flow Time"}  # tool column -> name in the training data
TIME_FORMATS = ("%d/%m/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S")
SCHEMA = """CREATE TABLE IF NOT EXISTS shadow (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, service TEXT, port INTEGER,
            packets INTEGER, duration_s REAL, supervised REAL, anomaly INTEGER, decision TEXT);
            CREATE INDEX IF NOT EXISTS shadow_ts ON shadow(ts);"""


def signed_log(v: str) -> float:
    """The training transform (src/cicids2017.py): NaN or infinity -> 0, then sign(x) * log(1 + |x|)."""
    try:
        x = float(v)
    except ValueError:
        return 0.0
    return math.copysign(math.log1p(abs(x)), x) if math.isfinite(x) else 0.0


UNPARSED: set[str] = set()  # timestamps in an unknown format, reported so the format list can be fixed


def when(stamp: str) -> str:
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(stamp.strip(), fmt).strftime("%Y-%m-%dT%H:%M:%SZ")  # captures are in UTC
        except ValueError:
            pass
    UNPARSED.add(stamp)
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def honeypot_flows(path: Path):
    """Rows of one CICFlowMeter CSV that are connections to a fake service on this server, columns renamed."""
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        head = [RENAME.get(h.strip(), h.strip()) for h in next(reader, [])]
        for values in reader:
            row = dict(zip(head, values))
            try:
                port, dst = int(row["Dst Port"]), ipaddress.ip_address(row["Dst IP"].strip())
            except (KeyError, ValueError):
                continue
            if port in SERVICES and dst.is_private:  # inbound to this server; the capture filter already ensures it
                yield row


class Shadow:
    def __init__(self, model_dir: Path):
        card = json.loads((model_dir / "card.json").read_text())
        self.features, self.cut = card["features_order"], card["anomaly_threshold"]
        self.alert, self.review = card["thresholds"]["alert"], card["thresholds"]["review"]
        self.sup = ort.InferenceSession(str(model_dir / "supervised.onnx"))
        self.iso = ort.InferenceSession(str(model_dir / "anomaly.onnx"))

    def score(self, rows: list[dict]) -> list[dict]:
        missing = [f for f in self.features if f not in rows[0]]
        if missing:
            raise ValueError(f"flow CSV lacks model features: {missing}")
        x = np.array([[signed_log(r[f]) for f in self.features] for r in rows], dtype=np.float32)
        proba = self.sup.run(["probabilities"], {"x": x})[0][:, 1]
        scores = self.iso.run(["scores"], {"x": x})[0].ravel()
        out = []
        for r, p, s in zip(rows, proba, scores):
            anomaly = bool(s < self.cut)
            decision = "ALERT" if p >= self.alert else "REVIEW" if (p >= self.review or anomaly) else "ALLOW"
            port = int(r["Dst Port"])
            out.append({"ts": when(r.get("Timestamp", "")), "service": SERVICES[port], "port": port,
                        "packets": int(float(r["Total Fwd Packet"]) + float(r["Total Bwd packets"])),
                        "duration_s": float(r["Flow Duration"]) / 1e6, "supervised": float(p),
                        "anomaly": int(anomaly), "decision": decision})
        return out


def store(db: Path, records: list[dict]):
    con = sqlite3.connect(db, timeout=30)
    with con:
        con.executescript(SCHEMA)
        con.executemany("INSERT INTO shadow (ts, service, port, packets, duration_s, supervised, anomaly, decision) "
                        "VALUES (:ts, :service, :port, :packets, :duration_s, :supervised, :anomaly, :decision)", records)
    con.close()


def main(flows: Path, db: Path, model_dir: Path) -> int:
    rows = [r for path in sorted(flows.glob("*.csv")) for r in honeypot_flows(path)]
    records = Shadow(model_dir).score(rows) if rows else []
    store(db, records)
    counts = {d: sum(r["decision"] == d for r in records) for d in ("ALERT", "REVIEW", "ALLOW")}
    print(f"scored {len(records)} honeypot flows: {counts}")
    if UNPARSED:
        print(f"warning: {len(UNPARSED)} timestamps in an unknown format, stored as now, e.g. {sorted(UNPARSED)[0]!r}")
    return len(records)


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2] if len(sys.argv) > 2 else "/data/tracker.db"),
         Path(sys.argv[3] if len(sys.argv) > 3 else "/model"))
