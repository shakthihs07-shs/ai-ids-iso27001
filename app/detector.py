"""Hybrid detector used by the live service: supervised model + anomaly layer + three decision bands.

The bands follow the human-in-the-loop policy tested in src/guardrails.py:
  ALERT   supervised score >= 0.7                         (known attack pattern, raise an alert)
  REVIEW  supervised score 0.2-0.7, or flagged as anomaly  (analyst queue: possible novel attack)
  ALLOW   everything else
"""
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))  # reuse the research preprocessing (signed_log) when unpickling

ALERT_AT, REVIEW_AT = 0.7, 0.2
ALERT, REVIEW, ALLOW = "ALERT", "REVIEW", "ALLOW"

# CIC-IDS2017 label -> MITRE ATT&CK technique, shown next to replayed flows (ground truth, not a model output)
MITRE = {
    "DoS Hulk": "T1499.002 Service Exhaustion Flood", "DoS GoldenEye": "T1499.002 Service Exhaustion Flood",
    "DoS Slowloris": "T1499.002 Service Exhaustion Flood", "DoS Slowhttptest": "T1499.002 Service Exhaustion Flood",
    "DDoS": "T1498.001 Direct Network Flood", "Heartbleed": "T1190 Exploit Public-Facing Application",
    "FTP-Patator": "T1110.001 Password Guessing", "SSH-Patator": "T1110.001 Password Guessing",
    "Web Attack - Brute Force": "T1110.001 Password Guessing", "Web Attack - XSS": "T1189 Drive-by Compromise",
    "Web Attack - SQL Injection": "T1190 Exploit Public-Facing Application",
    "Infiltration": "T1204.002 Malicious File", "Infiltration - Portscan": "T1046 Network Service Discovery",
    "Portscan": "T1046 Network Service Discovery", "Botnet": "T1071.001 Web Protocols (C2)",
}


def decide(supervised, anomaly):
    supervised, anomaly = np.asarray(supervised), np.asarray(anomaly, dtype=bool)
    return np.where(supervised >= ALERT_AT, ALERT, np.where((supervised >= REVIEW_AT) | anomaly, REVIEW, ALLOW))


class Detector:
    def __init__(self, path):
        art = joblib.load(path)
        self.features, self.supervised, self.iso, self.cut = art["features"], art["supervised"], art["iso"], art["cut"]
        self.card = art["card"]

    def score(self, flows: pd.DataFrame) -> pd.DataFrame:
        X = flows[self.features]
        sup = self.supervised.predict_proba(X)[:, 1]
        anomaly_score = -self.iso.score_samples(X)
        anomaly = anomaly_score > self.cut
        return pd.DataFrame({"supervised": sup, "anomaly_score": anomaly_score, "anomaly": anomaly,
                             "decision": decide(sup, anomaly)}, index=flows.index)
