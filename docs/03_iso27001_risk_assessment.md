# 03 – ISO/IEC 27001:2022 Risk Assessment: Deploying an ML-based IDS

## 1. Scope

Risk assessment for introducing the ML intrusion detection service (`docs/01_threat_model.md`) into the SOC of a **hypothetical mid-size IT services company in India** (~500 employees, ISO/IEC 27001:2022 certified). In scope: the detection model, training data, feature pipeline, decision thresholds, SIEM integration and the incident process. Regulatory context: CERT-In Directions 2022 and the DPDP Act 2023.

## 2. Method (ISO/IEC 27005 aligned)

- **Identify:** assets, threats and vulnerabilities from the STRIDE + AI threat model and from **measured test results** (not assumptions).
- **Analyse:** Likelihood (1–5) × Impact (1–5) = score 1–25.
  - Likelihood: 1 Rare · 2 Unlikely · 3 Possible (yearly) · 4 Likely (quarterly) · 5 Almost certain (monthly)
  - Impact: 1 Negligible · 2 Minor · 3 Moderate · 4 Major (data breach / regulatory report) · 5 Severe (large breach, fines, outage)
- **Evaluate:** Low 1–4 · Medium 5–9 · High 10–15 · Critical 16–25. **Acceptance criterion: residual score ≤ 9**, signed off by the risk owner; above 9 needs CISO sign-off.
- **Treat:** modify (controls), avoid, share, retain. Controls selected from ISO/IEC 27001:2022 Annex A.

## 3. Risk register summary

Full register with evidence, actions and owners: **`risk_register.xlsx`** / `risk_register.csv`.

| ID | Risk | Owner | Inherent | Residual | Key Annex A controls |
|---|---|---|---|---|---|
| R01 | Novel attack types not detected | SOC Lead | **20 Critical** | **12 High** – CISO sign-off | 5.7, 8.16, 8.7 |
| R02 | Credential/default-account attacks invisible to flow IDS | IAM Lead | **20 Critical** | 8 Medium | 5.17, 5.18, 8.5, 8.9, 8.15 |
| R03 | Exploits, privilege escalation, tunnelling missed | IT Ops Manager | 15 High | 8 Medium | 8.7, 8.8, 8.9, 8.20, 8.23 |
| R04 | Management over-trusts lab accuracy | CISO | **16 Critical** | 6 Medium | 5.8, 8.29, 5.36 |
| R05 | Model drift degrades detection | ML Engineer | **16 Critical** | 8 Medium | 8.16, 8.32, 5.37 |
| R06 | Adversarial evasion | ML Engineer | 12 High | 8 Medium | 8.16, 8.20, 8.29 |
| R07 | Alert fatigue from false positives | SOC Lead | 12 High | 6 Medium | 5.25, 5.26, 8.16 |
| R08 | Personal data in logs/training data (DPDP) | DPO | 12 High | 6 Medium | 5.34, 8.10, 8.11, 8.3 |
| R09 | Training data poisoning | ML Engineer | 10 High | 5 Medium | 8.3, 8.4, 5.33 |
| R10 | Unapproved model changes | IT Ops Manager | 8 Medium | 4 Low | 8.31, 8.32, 8.2 |
| R11 | Decisions not explainable | SOC Lead | 9 Medium | 4 Low | 5.28, 8.15, 5.37 |
| R12 | CERT-In 6 h / DPDP 72 h deadlines missed | CISO | 12 High | 4 Low | 5.24, 5.26, 5.31, 8.17 |
| R13 | IDS overload / single point of failure | IT Ops Manager | 8 Medium | 4 Low | 8.6, 8.14, 8.16 |
| R14 | Key-person dependency / skills gap | CISO | 12 High | 6 Medium | 6.3, 5.37 |

**Profile:** 4 Critical, 7 High, 3 Medium before treatment → 0 Critical, 1 High, 9 Medium, 4 Low after treatment. **R01 stays above the acceptance criterion**: even with the anomaly layer, about a third of novel attacks are still missed, so the CISO must formally accept it or fund further controls.

## 4. Annex A controls used – Statement of Applicability extract

| Control | Title | Why it applies here |
|---|---|---|
| 5.7 | Threat intelligence | New attack samples and IOCs to retrain for novel attacks (R01) |
| 5.8 | Information security in project management | Security acceptance criteria before go-live (R04) |
| 5.17 / 5.18 | Authentication information / Access rights | Compensate for blind spot on password guessing and default accounts (R02) |
| 5.24–5.28 | Incident management (planning, assessment, response, learning, evidence) | Alerts feed the incident process; evidence kept for investigations (R07, R11, R12) |
| 5.31 | Legal, statutory, regulatory requirements | CERT-In, DPDP obligations (R12) |
| 5.33 | Protection of records | Integrity of training data and scored events (R09) |
| 5.34 | Privacy and protection of PII | Personal data in network logs (R08) |
| 5.36 | Compliance with policies and standards | Model card reviewed against acceptance criteria (R04) |
| 5.37 | Documented operating procedures | Retraining, threshold and drift runbooks (R05, R14) |
| 6.3 | Awareness, education and training | Train analysts on model behaviour (R14) |
| 8.2 | Privileged access rights | Restrict who can deploy models (R10) |
| 8.5 | Secure authentication | MFA and lockout (R02) |
| 8.6 | Capacity management | Scoring throughput under attack load (R13) |
| 8.7 | Protection against malware | EDR as second detection layer (R01, R03) |
| 8.8 | Management of technical vulnerabilities | Patching for exploit-based attacks (R03) |
| 8.9 | Configuration management | Remove default SNMP/FTP settings (R02) |
| 8.10 / 8.11 | Information deletion / Data masking | Retention limits and pseudonymisation (R08) |
| 8.14 | Redundancy | Fail-over to signature IDS (R13) |
| 8.15 | Logging | Scored events, model version, failed logins (R02, R11) |
| 8.16 | Monitoring activities | The IDS itself plus drift monitoring (R01, R05, R06, R07) |
| 8.17 | Clock synchronisation | NTP for CERT-In log requirements (R12) |
| 8.20 / 8.23 | Network security / Web filtering | Egress filtering, WAF (R03, R06) |
| 8.29 | Security testing in development and acceptance | Acceptance and adversarial testing (R04, R06) |
| 8.31 / 8.32 | Separation of environments / Change management | Model releases (R05, R10) |

## 5. Treatment plan and sign-off

| Priority | Actions | Owner | Due |
|---|---|---|---|
| 1 | MFA + lockout + failed-login SIEM rule; remove default SNMP/FTP credentials | IAM Lead | Q1 |
| 2 | Deploy hybrid detection (supervised + anomaly layer + signatures) | SOC Lead | Q1 |
| 3 | Acceptance test on own labelled traffic; model card approved | CISO | Before go-live |
| 4 | Monthly PSI drift report and retraining runbook under change management | ML Engineer | Q1 |
| 5 | DPIA update, pseudonymisation, 180-day retention | DPO | Q2 |

Risk owners review residual risk quarterly; the register is re-assessed after each retraining or significant change to the network.

## 6. Same deployment under EU / German law

The scenario organisation is Indian, but the risks and controls above transfer directly. Only the legal obligations behind R08, R12 and control 5.31 change. If the same IDS were deployed by a comparable IT services company in Germany:

| Obligation | India (scenario above) | EU / Germany | Risks affected |
|---|---|---|---|
| Incident reporting | CERT-In Directions 2022: report within 6 h | **NIS2** (Directive (EU) 2022/2555, Art. 23): early warning within **24 h**, incident notification within **72 h**, final report within **one month**. In Germany reports go to the **BSI** under the BSIG as amended for NIS2. A mid-size managed IT service provider is likely in scope; the entity classification has to be confirmed | R12 |
| Personal-data breach | DPDP Act 2023: report to the Data Protection Board | **GDPR Art. 33**: notify the supervisory authority within **72 h**; Art. 34: inform data subjects when the risk to them is high | R08, R12 |
| Lawful basis for processing logs | DPDP: processing purpose recorded | **GDPR Art. 6(1)(f)** legitimate interest; Recital 49 names network and information security as such an interest. Balancing test documented | R08 |
| Log retention | CERT-In: 180 days | No fixed period. **GDPR Art. 5(1)(e)** storage limitation: the 180 days in this assessment must be justified by investigation needs and documented | R08, R11 |
| Impact assessment | DPIA recommended | **GDPR Art. 35 DPIA** required where systematic monitoring creates high risk; covers training data and scored events | R08 |
| Employee monitoring | — | **§ 87(1) no. 6 BetrVG**: a technical system able to monitor employee behaviour needs works-council co-determination before go-live | R08, R04 |
| Security risk management | ISO/IEC 27001 (voluntary) | **NIS2 Art. 21** risk-management measures (incident handling, supply chain, testing effectiveness). The Annex A controls in Section 4 provide most of the evidence | All |
| AI regulation | None specific | **EU AI Act** (Regulation (EU) 2024/1689): an AI component used solely for cybersecurity is generally not a high-risk "safety component" (Recital 55). Art. 4 **AI literacy** obligations apply to staff operating it (R14). It would become high-risk if repurposed to monitor or evaluate employee behaviour (Annex III, point 4) | R14, R08 |

**What changes in the register:** R12's deadline is the strictest in each regime: 6 h in India, 24 h in the EU. The playbook timer, NTP synchronisation and tabletop exercise stay the same. R08 gains the works-council agreement and the Art. 6(1)(f) balancing test as treatment actions. No inherent or residual scores change.
