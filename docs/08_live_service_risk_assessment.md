# 08 – Risk assessment: the live service

Corrective action for internal audit finding **NC-01** ([07](07_internal_audit_2026-11.md)): the existing register
([03](03_iso27001_risk_assessment.md)) assesses a hypothetical SOC deployment, so the live service had no risk
assessment of its own. This one covers the scope of the evidence pack ([06 §1](06_grc_evidence_pack.md#1-scope)),
and links every risk to the Annex A controls in the Statement of Applicability that treat it.

**Source:** [`grc/risk_register_live.csv`](../grc/risk_register_live.csv). Scores, ratings and the per-control
"Risks treated" column are computed into [`grc/soa.xlsx`](../grc/soa.xlsx); [`tests/test_soa.py`](../tests/test_soa.py)
fails if a risk names a control that is unknown or not applicable, if a decision contradicts the acceptance
criterion, or if the table below drifts from the register.

## 1. Method

The same ISO/IEC 27005-style method as [03](03_iso27001_risk_assessment.md#2-method-iso-iec-27005-aligned):
likelihood 1–5 × impact 1–5; Low 1–4, Medium 5–9, High 10–15, Critical 16–25. **Acceptance criterion: residual
score ≤ 9.** Risks above it must be treated further. Inherent scores assume none of the listed controls; residual
scores reflect the controls as they operate today, including the gaps in the SoA. Risk owner for every risk: the
operator, who also signs off acceptance.

Threats were identified from the incident register (06 §6), the attacks the honeypot actually receives, the
supplier register (06 §4) and the audit findings.

## 2. Risk register

| ID | Risk | Asset | Inherent | Key controls | Residual | Decision |
|---|---|---|---|---|---|---|
| LR01 | Honeypot VM compromised and abused | Honeypot VM | **15 High** | 8.20 firewall, 8.9 container hardening, 8.8 patching, 8.7 low interaction | 8 Medium | Accept |
| LR02 | Admin access stolen | Admin SSH key, operator's laptop | **15 High** | 5.17 passphrase, 8.5 key-only SSH, 8.2 no root login, 8.1 endpoint | **10 High** | **Treat** |
| LR03 | Provider account takeover | GitHub and Oracle accounts | **12 High** | 8.5 two-factor, 8.4 and 8.32 branch protection | 8 Medium | Accept |
| LR04 | Personal data exposed | Raw log, tracker database | **12 High** | 8.11 masking, 8.10 deletion, 5.34 privacy, 8.24 cryptography | 4 Low | Accept |
| LR05 | Attacker content attacks visitors | Public tracker page | **12 High** | 8.26 hostile input, 8.28 escaping, 8.21 CSP, 8.29 tests | 3 Low | Accept |
| LR06 | Tracker unavailable | Honeypot VM, tracker API | 8 Medium | 8.16 monitoring, 8.6 capacity, 5.30 rebuild, 5.23 cloud account | 6 Medium | Accept |
| LR07 | Wrong statistics published | Tracker statistics | 9 Medium | 8.29 tests, 8.32 change management, 5.27 lessons from incidents | 6 Medium | Accept |
| LR08 | Public links distrusted or broken | Public links | 9 Medium | 5.19 and 5.22 supplier management | 6 Medium | Accept |
| LR09 | Compromised or vulnerable dependency | Software supply chain | **12 High** | 5.21 pinning and checksums, 8.8 Dependabot, 8.25 CI | 8 Medium | Accept |
| LR10 | API overloaded | Tracker API | 6 Medium | 8.6 limits, 8.21 | 4 Low | Accept |
| LR11 | Legal or licence non-compliance | Honeypot data, datasets | 8 Medium | 5.31 GDPR record, 5.32 licences, 5.34 | 4 Low | Accept |
| LR12 | Code or evidence lost | Repository, evidence | 6 Medium | 8.13 copies, 8.32 deletion blocked, 5.33 | 3 Low | Accept |
| LR13 | Flow tool exploited by crafted packets (shadow mode, [09](09_shadow_mode.md)) | Honeypot VM | **12 High** | 8.22 no network, 8.27 read-only and no capabilities, 8.19 pinned build | 4 Low | Accept |

Full threat descriptions and every linked control: [`grc/risk_register_live.csv`](../grc/risk_register_live.csv).

**Profile:** before treatment 7 High and 6 Medium; after treatment 1 High, 6 Medium and 6 Low. No risk is Critical.
LR13 was added with shadow mode on 2026-11-21: the flow tool bundles a Log4Shell-era log4j and a native packet
parser and reads attacker-controlled packets, so it runs without network, read-only and without capabilities.

## 3. Treatment and acceptance

**LR02, admin access stolen: treat.** Residual 10 is above the criterion. The key's passphrase and key-only SSH
already lower the likelihood, but the laptop that holds the key does not meet the endpoint requirements (SoA 8.1,
7.9; details kept private). Treatment: bring the laptop to a supported, patched operating system and resolve disk
encryption. Due 2026-12-31. Expected residual afterwards: likelihood 1, score 5 Medium.

**Accepted (residual ≤ 9):** LR01, LR03 to LR13, signed off by the risk owner on 2026-11-21. Improvements already
planned still lower some of them further: Oracle two-factor authentication (LR03), confirmed scheduled monitoring,
Pay As You Go and a rebuild drill (LR06), and a custom domain (LR08).

## 4. Traceability to the Statement of Applicability

55 of the 82 applicable controls treat at least one risk; [`grc/soa.xlsx`](../grc/soa.xlsx) lists the risks for
each in its "Risks treated" column. The other 27 are **baseline** controls, kept for reasons other than a single
risk:

- **Management system:** 5.1, 5.2, 5.4, 5.5, 5.6, 5.8, 5.9, 5.10, 5.12, 5.13, 5.20, 5.35, 5.36
- **People:** 6.3, 6.7
- **Physical, inherited from the providers:** 7.1, 7.2, 7.4, 7.5, 7.6, 7.8, 7.11, 7.12, 7.13, 7.14
- **Testing and audit:** 8.33, 8.34

## 5. Review

Reviewed quarterly with the evidence refresh, after every incident, and after significant changes such as a new
supplier, a new public endpoint or a change of hosting (ISO/IEC 27001 8.2).
