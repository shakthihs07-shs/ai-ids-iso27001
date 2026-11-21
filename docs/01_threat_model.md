# 01 – Threat Model: ML-based Network IDS

## Scope and context

**System:** a machine-learning network intrusion detection service that scores every network connection record and sends alerts to the SIEM.

**Scenario organisation (hypothetical, used for the risk assessment):** a mid-size IT services company in India (~500 employees, ISO/IEC 27001:2022 certified, SOC monitored 24x7). In regulatory scope: **CERT-In Directions 2022** (6-hour incident reporting, 180-day log retention in India) and the **DPDP Act 2023** (network logs contain personal data such as IP addresses and usernames).

**Model evaluated in this repo:** soft-voting ensemble of Random Forest, Gradient Boosting and an MLP neural network, trained on NSL-KDD (see `docs/04_findings_report.md`).

## Data flow

```
 Network taps / firewall logs
            │  (1) raw traffic, contains personal data
            ▼
 Feature extraction  ──► 41 connection features (bytes, flags, rates, service)
            │  (2)
            ▼
 ML scoring service  ──► attack probability 0–1      ◄── (5) model + training data repository
            │  (3)                                          (retraining pipeline)
            ▼
 Decision layer: ≥0.7 auto-alert/block · 0.2–0.7 analyst queue · <0.2 allow
            │  (4)
            ▼
 SIEM  ──►  SOC analyst  ──►  Incident response (CERT-In 6 h report, DPDP Board report)
```

**Trust boundaries:** (a) between the monitored network and the sensor; (b) between the ML service and the model/data repository; (c) between automated decisions and human analysts.

## STRIDE analysis

| # | Element | STRIDE | Threat | Example in this system |
|---|---|---|---|---|
| T1 | Sensor → features | **Spoofing** | Attacker spoofs source IPs | Smurf / reflection attacks hide the real source |
| T2 | Training data | **Tampering** | Data poisoning | Insider adds mislabeled "normal" samples of a future attack |
| T3 | Model artefact | **Tampering** | Unauthorised model swap | Weakened model deployed without change approval |
| T4 | Alerts / decisions | **Repudiation** | No record of why traffic was blocked | Analyst cannot justify an auto-block in an audit |
| T5 | Logs and features | **Information disclosure** | Personal data in logs leaks | IP addresses, usernames exposed via SIEM or training sets |
| T6 | Model | **Information disclosure** | Model inversion / extraction | Attacker queries the model to learn its decision boundary |
| T7 | Scoring service | **Denial of service** | Flood overloads the IDS | High-volume attack exceeds scoring throughput, IDS fails open |
| T8 | Analyst queue | **Denial of service** | Alert flooding / fatigue | Many false positives bury real alerts |
| T9 | Model admin / pipeline | **Elevation of privilege** | Over-privileged ML accounts | Data scientist can push to production without review |

## AI-specific threats (MITRE ATLAS style)

| # | Threat | What it means | Evidence from this project |
|---|---|---|---|
| A1 | **Evasion** | Attacker changes traffic so the model scores it as normal | Padding bytes and duration made **~17% of detected attacks evade** the ensemble |
| A2 | **Novel attacks** | Attack types not present in training data | Recall on 17 unseen attack types: **39.5%** vs **78.2%** on known types |
| A3 | **Concept drift** | Live traffic differs from training traffic | **5 features** of normal traffic show moderate PSI shift (0.10–0.12) |
| A4 | **Data poisoning** | Corrupted training labels | Not tested – mitigated by data integrity controls |
| A5 | **Over-trust in lab results** | Decisions based on in-lab accuracy | **99.9% F1 in cross-validation vs 79.2% F1 on the realistic test set** |
| A6 | **Blind spots by design** | Flow features can't see some attacks | **0% detection** of password guessing (T1110.001) and default-account abuse via SNMP |

## Mapping to ATT&CK

Detection coverage per ATT&CK technique is in `docs/02_mitre_attack_mapping.md`. The threat model feeds the risk register in `docs/03_iso27001_risk_assessment.md`.
