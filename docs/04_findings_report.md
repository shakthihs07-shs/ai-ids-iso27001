# 04 – Security Findings Report: ML-based Intrusion Detection on NSL-KDD and CIC-IDS2017

**Author:** Shakthi H S · **Date:** November 2026 · **Status:** Final

## Executive summary

I built and tested a machine-learning intrusion detection system on the NSL-KDD benchmark and assessed the risk of deploying it in a SOC.

- **Lab results are misleading.** Inside the training data (5-fold cross-validation) the models reach **99.9% F1**. On the realistic test set, which contains 17 attack types never seen in training, the best model reaches **79.6% F1**. That is a 20-point gap.
- **Best single model: Gradient Boosting** – F1 79.6%, precision 96.9%, recall 67.6%, false-positive rate 2.8%.
- **New attacks are the main weakness.** The ensemble detects 78% of known attack types but only **39.5% of novel ones**.
- **A hybrid design fixes much of it.** Adding an anomaly detector trained only on normal traffic raises novel-attack detection to **65.9%** and overall recall from 66.9% to **76.0%**, for +0.5 points of false positives.
- **Flow-based ML is blind to credential attacks.** Password guessing (MITRE T1110.001) was detected **0%** of the time. Identity controls (MFA, lockout, failed-login alerts) are required, not a better model.
- **The model can be evaded.** Padding traffic made **~17%** of detected attacks score as normal.
- **A modern dataset confirms it.** On CIC-IDS2017 (corrected labels, 2023), the same models catch **99.99%** of known attack types but only **3.2%** of the 8 attack types they never saw; the anomaly layer lifts that to **73.6%** (section 7).
- Risk assessment: **14 risks**, 4 Critical before treatment, 1 High remaining after treatment (novel attacks), which needs CISO acceptance.

## 1. Data

| | Training (KDDTrain+) | Test (KDDTest+) |
|---|---|---|
| Records | 125,973 | 22,544 |
| Attack share | 46.5% | 56.9% |
| Attack types | 22 | 37 (17 never seen in training, 3,750 records) |
| Normal / DoS / Probe / R2L / U2R | 67,343 / 45,927 / 11,656 / 995 / 52 | 9,711 / 7,458 / 2,421 / 2,754 / 200 |

41 features per connection (duration, protocol, service, flag, bytes, error rates, host-level counts). Preprocessing: one-hot encoding for protocol/service/flag, log transform for heavy-tailed counts, standard scaling for SVM and MLP. All preprocessing is fitted on training data only.

**Why NSL-KDD:** it removes the duplicate records of KDD Cup 99, and its test set deliberately contains new attack types and harder records – a good stand-in for "production differs from training".

## 2. Models

| Model | Setup |
|---|---|
| Random Forest | 200 trees |
| Gradient Boosting | HistGradientBoosting, 300 iterations |
| SVM (RBF) | C = 10; trained on a stratified 25,000-row sample (RBF SVM does not scale to 126k rows) |
| Neural Net (MLP) | 128-64 hidden units, early stopping |
| Ensemble | Soft vote (average probability) of RF + GB + MLP |

## 3. Results – binary (attack vs normal), threshold 0.5

| Model | Accuracy | Precision | Recall | F1 | False-positive rate | ROC-AUC | Train time |
|---|---|---|---|---|---|---|---|
| Random Forest | 77.8% | 96.9% | 63.0% | 76.3% | **2.7%** | **0.962** | 7 s |
| **Gradient Boosting** | **80.3%** | **96.9%** | 67.6% | **79.6%** | 2.8% | 0.961 | 8 s |
| SVM (RBF, 25k rows) | 75.9% | 92.0% | 63.1% | 74.9% | 7.3% | 0.904 | 6 s |
| Neural Net (MLP) | 78.4% | 92.4% | **67.7%** | 78.1% | 7.4% | 0.923 | 17 s |
| Ensemble (RF+GB+MLP) | 80.0% | 96.9% | 66.9% | 79.2% | 2.8% | 0.962 | – |

Cross-validation on training data: Random Forest F1 **99.88%**, Gradient Boosting **99.91%**.

**Interpretation**
- Precision is high (≈97%): when the model raises an alert, it is almost always a real attack. Recall is the problem: about one in three attacks is missed.
- Tree models give the lowest false-positive rate; SVM and MLP produce 2.6x more false alarms.
- The ensemble did not beat Gradient Boosting on F1 here – combining models only helps when they make different mistakes.
- Training times are seconds, not hours, because NSL-KDD is small. Production-scale data would change that.

## 4. Results – by attack family

| Family | Recall on known types | Recall on novel types |
|---|---|---|
| DoS | 99.9% | 38.1% |
| Probe | 100% | 61.8% |
| R2L (remote to local) | 11.7% | 0.5% |
| U2R (user to root) | 21.6% | 8.0% |
| **All attacks** | **78.2%** | **39.5%** |

(Ensemble, threshold 0.5. Full table: `results/per_category_recall.csv`.)

Five-class Random Forest (`results/multiclass_report.txt`): Normal recall 97.4%, DoS 77.2%, Probe 59.3%, R2L 0.7%, U2R 1.0%. R2L and U2R are rare in training (995 and 52 records) and look like normal sessions at the flow level.

**Top features (Random Forest):** src_bytes 14.2%, dst_bytes 11.2%, flag = SF 6.0%, same_srv_rate 5.4%, diff_srv_rate 4.7%. The model relies heavily on volume features – which is exactly what the evasion test exploits.

## 5. Guardrail tests

Details: `docs/05_ai_guardrails.md`.

| Test | Result |
|---|---|
| Anomaly layer (Isolation Forest, normal-only training) | Novel-attack recall 39.5% → **65.9%**; overall recall 66.9% → **76.0%**; F1 79.2% → **85.1%**; FPR 2.8% → 3.3% |
| Threshold tuning | Threshold 0.05: recall **85.2%**, FPR **9.2%** – more detection, 3x the false alarms |
| Human-in-the-loop band | Auto-alert (score ≥ 0.7): 37.3% of events, 96.8% precise · Analyst queue (0.2–0.7): **6.4%** of events, 67.8% are attacks · Auto-allow (< 0.2): 56.3% |
| Drift (PSI, normal traffic only) | 5 features with moderate shift (dst_host_diff_srv_rate 0.117); none above 0.25 |
| Evasion | Padding bytes and duration: **16–17%** of detected attacks evade |

## 6. Findings and recommendations

| # | Finding | Severity | Recommendation | Risk |
|---|---|---|---|---|
| F1 | 20-point gap between lab and realistic performance | High | Never approve go-live on cross-validation or vendor numbers; test on own labelled traffic | R04 |
| F2 | Novel attacks detected only 39.5% | High | Hybrid: supervised + anomaly layer + signatures; quarterly retraining with threat intel | R01 |
| F3 | Password guessing and default-account abuse 0–23% detected | High | MFA, lockout, failed-login alerting, remove default credentials | R02 |
| F4 | 17% of detected attacks evade with simple padding | Medium | Adversarial training, rate-based features, red-team testing | R06 |
| F5 | Threshold choice drives the false-alarm load | Medium | Three-band decision policy with analyst review queue | R07 |
| F6 | Feature drift between training and live data | Medium | Monthly PSI monitoring with retraining triggers | R05 |
| F7 | Network logs and training data contain personal data | Medium | Pseudonymisation, 180-day retention, DPIA | R08 |

## 7. Repeat on a modern dataset: CIC-IDS2017

**Data.** CIC-IDS2017 with corrected labels (`CICIDS2017_improved`, Engelen et al., KU Leuven DistriNet, 2023): CICFlowMeter flows from five working days of a lab network with modern attacks. Download with `data/download_cicids2017.sh`, run with `python src/cicids2017.py`. Flows marked "Attempted" (attack traffic with no malicious effect) count as benign, as the authors advise. IPs, ports, flow ID and timestamp are dropped, so the models cannot learn the lab's addresses; 82 flow features remain.

**Split**, built like NSL-KDD's:

| | Rows | Attack share | Attack types |
|---|---|---|---|
| Train: 70% of Monday–Wednesday | 833,240 | 15.0% | 6 (DoS ×4, Heartbleed, FTP/SSH brute force) |
| Test: other 30% of Monday–Wednesday + all of Thursday–Friday | 1,266,736 | 30.0% | 14: 53,573 known-type rows, **326,853 rows of 8 types never seen** (port scan, DDoS, botnet, infiltration, 3 web attacks) |

**Results** (same models and settings as sections 2–5; `results/cicids2017/`):

| Detector | Known types | Novel types | False-positive rate | F1 |
|---|---|---|---|---|
| Supervised ensemble (RF+GB+MLP) | **99.99%** | **3.2%** | 0.00% | 28.8% |
| Best single model on novel types (Random Forest) | 99.98% | 28.7% | 0.00% | 55.9% |
| Anomaly layer alone (Isolation Forest) | 3.5% | 70.4% | 5.1% | 70.5% |
| **Hybrid (either layer)** | **99.99%** | **73.6%** | **5.1%** | **81.7%** |

**Interpretation**
- The NSL-KDD pattern repeats, more sharply. Known attack types are caught almost perfectly; novel ones almost never. On NSL-KDD the novel attacks were mostly variants of known families (39.5% caught); here they are new kinds of attack, and the supervised models have nothing to match them to.
- Port scans (0.0%), botnet (0%), infiltration (0%) and web attacks (0–8%) pass the supervised ensemble; DDoS is caught 11% of the time even though four DoS tools were in training.
- The supervised models raise almost no false alarms on the later days' benign traffic. They do not fail noisily; they fail silently, which is the worse failure for a SOC.
- The MLP ranks traffic worse than chance on the new days (ROC-AUC 0.49): a model can look excellent in testing and invert under a shift.
- The anomaly layer again carries novel-attack detection, at its 5% alert budget. On this test set that is about 45,000 false alerts out of 886,000 benign flows: at production volumes it needs the analyst queue and tuning from section 5 (risks R01, R07).
- This strengthens findings F1, F2 and F5; the risk register is unchanged.

## 8. Limitations

- NSL-KDD is old (1998 traffic) and has no encrypted traffic, cloud workloads or modern malware. Section 7 repeats the core tests on CIC-IDS2017 (2017 traffic, labels corrected in 2023): the absolute numbers differ, the **patterns** (lab gap, novel-attack weakness, need for an anomaly layer) hold. CIC-IDS2017 is still a lab network, and its attacks run on separate days, so the day split also mixes attack novelty with day-to-day change in benign traffic.
- The MITRE mapping, drift, threshold and evasion tests and the risk register use NSL-KDD only.
- SVM trained on a sample, not the full set.
- Evasion test is a simple feature-space perturbation, not a full adversarial attack.
- The organisation in the risk assessment is hypothetical.

## 9. Next steps

1. Repeat on UNSW-NB15, and map CIC-IDS2017 attack types to MITRE ATT&CK.
2. Add SHAP explanations per alert.
3. Adversarial training and re-test evasion.
