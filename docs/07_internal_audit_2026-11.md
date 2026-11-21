# 07 – Internal audit, November 2026

**Audit:** IA-2026-11 · **Date:** 2026-11-21 · **Auditor:** Shakthi H S (operator; see observation OBS-01 on
independence) · **Audited:** the live service described in [06](06_grc_evidence_pack.md)

## Summary

The ISMS of the live service was audited against ISO/IEC 27001:2022 clauses 4 to 10 and a risk-based sample of
11 Annex A controls. Controls were **re-performed from the outside**, not only read: 25 automated tests against
the live server and GitHub ([`grc/audit_tests.sh`](../grc/audit_tests.sh)), plus document review.

| Result | Count |
|---|---|
| Audit tests passed | 24 of 25 |
| Major nonconformities | 1 |
| Minor nonconformities | 4 |
| Observations | 3 |
| Opportunities for improvement | 2 |

**Conclusion:** the technical controls sampled are effective, with one exception: monitoring (A.8.16) was designed
but not operating. The management-system layer is incomplete: there is no risk assessment for the actual scope, no
measurable objectives, no management review and no record of interested parties. These are typical gaps of a first
ISMS cycle. Corrective actions are planned below; the one for A.8.16 is already implemented.

## 1. Audit plan

| | |
|---|---|
| Objective | Determine whether the ISMS of the live service conforms to ISO/IEC 27001:2022 and whether the controls the SoA marks as implemented are effective |
| Scope | As in [06 §1](06_grc_evidence_pack.md#1-scope): honeypot VM, tracker API, demo pages, repository and CI, admin endpoint |
| Criteria | ISO/IEC 27001:2022 clauses 4–10 and Annex A; the pack's own policy statement and SoA ([`grc/soa.csv`](../grc/soa.csv)) |
| Method | Re-performance (automated tests run from outside the system), document review, inspection of GitHub settings and history, following ISO 19011 principles |
| Sample | Risk-based: controls that protect the internet-facing system or personal data, or that other controls depend on: A.6.8, A.8.2, A.8.5, A.8.10, A.8.11, A.8.15, A.8.16, A.8.20, A.8.21, A.8.24, A.8.32; plus A.5.24–5.27 and A.8.8 by document and settings review |
| Evidence | [`grc/evidence/audit-tests-2026-11-21.txt`](../grc/evidence/audit-tests-2026-11-21.txt), [`grc/evidence/vm-2026-11-21.txt`](../grc/evidence/vm-2026-11-21.txt), GitHub settings and history |

## 2. Clauses 4–10

| Clause | Requirement | Result | Evidence / finding |
|---|---|---|---|
| 4.1 | Context of the organization | Conforming | Purpose and setting in 06 §1–2 |
| 4.2 | Interested parties and their requirements | **NC-05** | Not documented |
| 4.3 | ISMS scope | Conforming | 06 §1, with exclusions |
| 5.1–5.3 | Leadership, policy, roles | Conforming | 06 §2 |
| 6.1.2 | Information security risk assessment | **NC-01 (major)** | The risk register ([03](03_iso27001_risk_assessment.md)) assesses a hypothetical SOC deployment, not the live service in scope |
| 6.1.3 | Risk treatment and Statement of Applicability | Conforming, see NC-01 | SoA complete for all 93 controls with justification; control selection is not yet traced to assessed risks of the live service |
| 6.2 | Information security objectives | **NC-03** | No measurable objectives defined |
| 6.3 | Planning of changes | Conforming | Changes through pull requests with CI (A.8.32 tests passed) |
| 7.1–7.5 | Resources, competence, awareness, communication, documented information | Conforming | Competence in README; contacts in 06 §2; documents versioned in git |
| 8.1 | Operational planning and control | Conforming | Scripted deployment, evidence and audit procedures |
| 8.2–8.3 | Risk assessment and treatment in operation | See NC-01 | Treatment plan exists in 06 §5; assessment missing for the scope |
| 9.1 | Monitoring, measurement, analysis | See NC-02, NC-03 | Monitoring not operating; nothing defined to measure against |
| 9.2 | Internal audit | Conforming from this audit | This report; programme in §6. Independence: OBS-01 |
| 9.3 | Management review | **NC-04** | None held yet |
| 10.1–10.2 | Continual improvement; nonconformity and corrective action | Conforming | Incident register with root cause, fix and lesson for all 8 incidents; INC-04's regression test exists |

## 3. Annex A sample

| Control | Test performed | Result |
|---|---|---|
| A.8.20 Networks security | Connected to 10 ports from outside: the 4 expected ones answer; the collector API (8000), Docker API (2375), rpcbind (111) and 3 others do not | Effective |
| A.8.5 Secure authentication | Admin SSH, password login attempted: server offers `publickey` only | Effective |
| A.8.2 Privileged access rights | Same test as `root`: no password method offered | Effective |
| A.8.24 Use of cryptography | Certificate trusted, valid until 2027-02-18; TLS 1.0 and 1.1 refused | Effective |
| A.8.21 Security of network services | HSTS and CSP sent; CORS granted to the demo site only, refused for another origin; public tracker page carries its own CSP | Effective |
| A.8.11 Data masking | 200 latest public events: all addresses truncated, no hash or password fields | Effective |
| A.8.10 Information deletion | Tracker retention 30 days, no older event; raw-log daily rotation deployed the same day | Effective; OBS-02 |
| A.8.15 Logging | 1,852 events logged in the last hour | Effective |
| A.8.16 Monitoring activities | Uptime workflow active since 15:47 UTC but **no scheduled run in over 2 hours**; only a manual run | **NC-02** |
| A.8.32 Change management | `main` requires a pull request and the CI test check; the last 3 changes were merged pull requests whose test check passed | Effective |
| A.6.8 Event reporting | Security policy published; private vulnerability reporting on | Effective |
| A.5.24–5.27 Incident management | All 8 incidents have cause, fix and lesson; the regression test promised for INC-04 exists | Effective |
| A.8.8 Technical vulnerabilities | 0 open Dependabot alerts; updates tested in CI before merging, including the honeypot images | Effective |

## 4. Findings

**Nonconformities**

| ID | Grade | Clause / control | Finding |
|---|---|---|---|
| NC-01 | Major | 6.1.2, 8.2 | No information security risk assessment covers the scope of the ISMS. The existing register assesses a hypothetical deployment, so the SoA's control choices are not traced to the risks of the system that actually runs |
| NC-02 | Minor | A.8.16, 9.1 | The uptime monitoring the SoA marked as implemented has never run on its schedule. Likely cause: the schedule fired at :00 and :30, the minutes GitHub most often delays or drops. A monitoring gap would have gone unnoticed |
| NC-03 | Minor | 6.2 | No measurable information security objectives |
| NC-04 | Minor | 9.3 | No management review has taken place |
| NC-05 | Minor | 4.2 | Interested parties and their requirements are not documented |

**Observations**

| ID | Observation |
|---|---|
| OBS-01 | The auditor is the operator, so the impartiality ISO 27001 asks of internal auditors (9.2.2) cannot be achieved. Mitigated by reproducible tests that anyone can re-run; an independent peer review stays planned (A.5.35) |
| OBS-02 | Daily rotation of raw honeypot logs was deployed on the audit day; its operation (at most 7 files, oldest at most 7 days) can only be confirmed at the next audit |
| OBS-03 | Gaps already in the SoA treatment plan are still open (Oracle two-factor authentication and account upgrade, laptop patch level and disk encryption, rebuild drill). Tracked, not raised again |

**Opportunities for improvement**

| ID | Opportunity |
|---|---|
| OFI-01 | Run `grc/audit_tests.sh` automatically every week, so control failures such as NC-02 surface within days instead of at the next audit |
| OFI-02 | Replace the sslip.io name with a custom domain to remove a supplier the business already had trouble with (INC-07) |

## 5. Corrective action plan

| Finding | Correction / corrective action | Due | Verification |
|---|---|---|---|
| NC-01 | Risk assessment of the live service (likelihood × impact, as in 03), with each SoA control linked to the risks it treats | 2026-12-31 | Next audit samples three risks and traces them to SoA controls |
| NC-02 | **Done 2026-11-21:** schedule moved to minutes 7 and 37; SoA 8.16 set to Partial until runs are confirmed | 2026-11-28 | `audit_tests.sh` test A.8.16 passes; at least 10 scheduled runs in a week |
| NC-03 | Define 4–6 measurable objectives (e.g. uptime, time to patch, time to close incidents, zero personal data published) | 2026-12-31 | Objectives documented with a measurement method |
| NC-04 | Hold the first management review using the 9.3.2 inputs (audit results, incidents, objectives, risks, changes) | 2026-12-31 | Minutes with decisions and actions |
| NC-05 | Document interested parties (visitors and recruiters, people whose addresses are processed, providers, the data protection authority) and their requirements | 2026-12-31 | Register in 06 |

## 6. Audit programme

| When | What |
|---|---|
| 2026-11-28 | Follow-up of NC-02: re-run `audit_tests.sh` |
| Quarterly from 2027-02 | Full re-run of `audit_tests.sh`, VM evidence refresh, follow-up of open corrective actions |
| Yearly | Clause 4–10 review, rotating Annex A sample, independent peer review (A.5.35) |

Re-run the tests: `bash grc/audit_tests.sh > grc/evidence/audit-tests-$(date -u +%F).txt`
