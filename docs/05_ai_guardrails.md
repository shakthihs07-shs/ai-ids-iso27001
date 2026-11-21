# 05 – AI Guardrails: Tests and Operating Controls

Guardrails are the controls that keep an ML detector safe to rely on after go-live. Each one below was **tested** (`src/guardrails.py`, outputs in `results/guardrails_*`).

## G1 – Hybrid detection for unknown attacks

**Risk:** the supervised model only knows attacks it was trained on (R01).
**Control:** an Isolation Forest trained **only on normal traffic**, threshold set so 5% of normal training traffic is flagged. An event is alerted if *either* layer flags it.

| Detector | Recall (all) | Known attacks | Novel attacks | FPR | F1 |
|---|---|---|---|---|---|
| Supervised ensemble | 66.9% | 78.2% | 39.5% | 2.8% | 79.2% |
| Anomaly layer alone | 66.0% | 66.8% | 64.0% | 2.7% | 78.6% |
| **Hybrid** | **76.0%** | **80.1%** | **65.9%** | 3.3% | **85.1%** |

The two layers fail on different attacks, so combining them adds real coverage.

## G2 – Alert threshold policy

**Risk:** a fixed threshold either misses attacks or floods analysts (R07).

| Threshold | Recall | Precision | FPR | Alerts per 10,000 events |
|---|---|---|---|---|
| 0.9 | 56.5% | 96.7% | 2.5% | 3,327 |
| 0.7 | 63.4% | 96.8% | 2.8% | 3,727 |
| **0.5** | **66.9%** | **96.9%** | **2.8%** | **3,930** |
| 0.3 | 69.7% | 92.6% | 7.4% | 4,289 |
| 0.1 | 77.1% | 92.7% | 8.0% | 4,729 |
| 0.05 | 85.2% | 92.4% | 9.2% | 5,249 |

Threshold is a **risk decision**, owned by the SOC Lead and reviewed monthly, not a data-science default.

## G3 – Human-in-the-loop band

| Score | Action | Share of events | Notes |
|---|---|---|---|
| ≥ 0.7 | Auto-alert / block | 37.3% | 96.8% are real attacks |
| 0.2 – 0.7 | **Analyst review queue** | **6.4%** | 67.8% are attacks – worth human time |
| < 0.2 | Allow (logged) | 56.3% | Still contains 3,712 of 12,833 attacks → why G1 and identity controls are needed |

## G4 – Drift monitoring

Population Stability Index (PSI) per feature, training vs live. Rule: **PSI > 0.25 on any feature, or validation recall drop > 5 points → retrain under change management.**

Measured on **normal traffic only**, training vs test: no feature above 0.25; 5 with moderate shift – dst_host_diff_srv_rate 0.117, src_bytes 0.115, dst_host_srv_count 0.111, dst_host_same_srv_rate 0.105, srv_count 0.103. The service mix of normal traffic also changed: http's share moved by 12 points.

PSI is computed on normal traffic only on purpose. The test set has more attacks than the training set (57% vs 46%). Comparing all traffic reports that change in attack share as drift: serror_rate would show 0.197 although its PSI on normal traffic is 0.000. In production, compute PSI on traffic the SOC has confirmed as benign, or the drift report mostly tracks how much attack traffic there was that month.

## G5 – Evasion testing

Detected attacks were modified to look "bigger and slower" (bytes × 1.5–10 + 200, duration + 1.5–10 s) and re-scored.

| Perturbation | Evasion rate |
|---|---|
| bytes ×1.5 +200, duration +1.5 s | 17.0% |
| bytes ×2 +200, duration +2 s | 16.9% |
| bytes ×5 +200, duration +5 s | 16.3% |
| bytes ×10 +200, duration +10 s | 16.2% |

Even small padding works because src_bytes and dst_bytes are the two most important features. Mitigations: adversarial training with padded samples, more weight on rate features, and the anomaly layer.

## G6 – Governance controls (not code)

- **Model card** per release: data, metrics, known blind spots (e.g. T1110 0%), owner, approval.
- **Change management** for every retrain or threshold change (ISO 27001 8.32), with rollback.
- **Explainability**: top contributing features attached to each alert so analysts and auditors can see why it fired.
- **Data protection**: pseudonymised training data, 180-day log retention (CERT-In), DPIA under DPDP.
- **Accountability**: automated blocks limited to high-confidence scores; people make the final call in the review band.
