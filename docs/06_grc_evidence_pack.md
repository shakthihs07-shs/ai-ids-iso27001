# 06 – GRC evidence pack: the live service

The risk assessment in [03](03_iso27001_risk_assessment.md) covers a *hypothetical* company deploying the
detector. This pack covers the system that actually runs: the live honeypot, the attack tracker and the
public demo. Every claim points to a file in this repository or to an evidence snapshot taken from the server,
and a test ([`tests/test_soa.py`](../tests/test_soa.py)) fails if an evidence file named in the Statement of
Applicability is missing.

It is a self-assessment for a one-person service, not a certification and not legal advice.

| Part | Content |
|---|---|
| [1](#1-scope) | Scope |
| [2](#2-security-policy-roles-and-review) | Security policy, roles and review |
| [3](#3-assets-and-classification) | Assets and classification |
| [4](#4-suppliers) | Suppliers |
| [5](#5-statement-of-applicability) | Statement of Applicability: all 93 Annex A controls ([`grc/soa.xlsx`](../grc/soa.xlsx)) |
| [6](#6-incident-management) | Incident playbook and the incident register (8 real incidents) |
| [7](#7-gdpr-record-of-processing) | GDPR: record of processing, legitimate-interest assessment, DPIA screening |
| [8](#8-eu-ai-act-and-nis2) | EU AI Act classification and NIS2 scope |
| [9](#9-model-card-deployed-detector) | Model card of the deployed detector |
| [10](#10-evidence-and-how-to-refresh-it) | Evidence and how to refresh it |
| [07](07_internal_audit_2026-11.md) | **Internal audit, November 2026:** findings and corrective actions for this pack |
| [08](08_live_service_risk_assessment.md) | **Risk assessment of the live service:** 13 risks, each traced to the SoA controls that treat it |
| [09](09_shadow_mode.md) | **Shadow mode:** the detector scores real honeypot traffic; design, privacy, limits and results |

## 1. Scope

**In scope:** the honeypot VM on Oracle Cloud (Frankfurt) with OpenCanary, the collector and the Caddy web
server; the tracker API; the public pages on GitHub Pages (results dashboard, live IDS console, attack tracker);
this repository and its CI; the operator's laptop as the only admin endpoint.

**Out of scope:** the hypothetical SOC deployment (covered by [03](03_iso27001_risk_assessment.md)) and the
providers' own infrastructure (inherited controls, see section 4).

## 2. Security policy, roles and review

**Policy statement (A.5.1).** The service exists to show real attacks safely. It must never give an attacker
a foothold, never publish data that identifies a person, and stay honest about what it measures. Concretely:

- Administration only by SSH key on a separate port; no passwords anywhere (A.5.15, A.8.5).
- Everything an attacker sends is hostile input: cleaned, capped, escaped, never executed (A.8.26, A.8.28).
- Personal data is minimised before it is stored and deleted on a fixed schedule (A.5.34, A.8.10, A.8.11).
- Every change reaches `main` through a pull request that must pass CI, enforced by a branch ruleset;
  configuration lives in the repository (A.8.9, A.8.32).
- Incidents are recorded with a cause and a lesson, and a regression test where possible (A.5.26, A.5.27).

**Roles (A.5.2).** One person, Shakthi H S, is owner, administrator, incident handler and data controller.
Segregation of duties is therefore not possible (A.5.3 not applicable). The compensating control: a branch
ruleset lets a change reach `main` only through a pull request that passes CI.

**Review (A.5.4, A.5.36).** Quarterly: re-collect the VM evidence (section 10), review the gaps in section 5,
review access, update this pack. After every incident: update section 6.

**Contacts (A.5.5).**

| For | Contact |
|---|---|
| A security incident affecting others (e.g. the VM is abused) | BSI / CERT-Bund, Germany's national CERT |
| A personal-data breach | The Berlin data protection authority (Berliner Beauftragte für Datenschutz und Informationsfreiheit), within 72 hours (GDPR Art. 33) |
| Abuse from or to the VM | Oracle Cloud's abuse reporting |
| Vulnerability reports from the public | GitHub private vulnerability reporting ([SECURITY.md](../SECURITY.md)) |

## 3. Assets and classification

Classes (A.5.12): **Public** (meant to be published), **Internal** (not published, low harm if exposed),
**Confidential** (harm or legal duty if exposed).

| Asset | Where | Class | Owner | Notes |
|---|---|---|---|---|
| Source code, docs, results, risk register | GitHub (public repo), laptop | Public | Operator | MIT licence |
| Demo pages and ONNX models | GitHub Pages | Public | Operator | |
| Tracker statistics and masked events | VM (SQLite), API | Public | Operator | Masked before storage, 30 days |
| Raw honeypot log | VM, root-only volume | Confidential | Operator | Full source addresses and attempted passwords; 7 days |
| Admin SSH key | Operator's laptop | Confidential | Operator | Passphrase-protected, held in the ssh-agent (A.5.17) |
| GitHub and Oracle accounts | Providers | Confidential | Operator | GitHub: 2FA on. Oracle: gap, confirm 2FA (A.8.5) |
| Operator's laptop | Operator | Confidential | Operator | Only admin endpoint; checked with `grc/check_endpoint.ps1`, results kept privately (A.8.1) |
| Honeypot VM | Oracle Cloud, Frankfurt | Internal | Operator | Always Free E2.1.Micro |
| Evidence snapshots | This repository | Public | Operator | No secrets by design |

Acceptable use (A.5.10): honeypot data is used for research and public statistics only. Nobody tries to
re-identify sources, and raw logs are never shared.

## 4. Suppliers

| Supplier | Provides | Risk it brings | Handling |
|---|---|---|---|
| Oracle Cloud | The VM, network, data centre | Idle Always Free VMs can be reclaimed; account in Free Trial | Uptime check alerts; gap: upgrade to Pay As You Go (A.5.23) |
| GitHub | Code hosting, CI, Pages, secret scanning | Account takeover would expose the demo | Two-factor authentication with an authenticator app (A.8.5) |
| Let's Encrypt | TLS certificate | Renewal failure breaks the API | Caddy renews automatically; certificate dates in the evidence snapshot |
| sslip.io | DNS name for the VM | LinkedIn flags the whole domain as possibly malicious (INC-07) | Public links point to GitHub Pages only; a custom domain is planned |
| DB-IP | IP-to-country database (CC BY 4.0) | Download blocked (INC-01) | Fetched at build time with a fallback month; credited on the page |
| PyPI, Docker Hub, GitHub Actions | Dependencies | Vulnerable or compromised packages | Pinned honeypot versions, Dependabot alerts and updates |

Physical controls (A.7.1–7.6, 7.8, 7.11–7.14) are inherited from Oracle and GitHub, both certified to
ISO/IEC 27001.

## 5. Statement of Applicability

Full SoA with justification, evidence and gaps for every control: [`grc/soa.csv`](../grc/soa.csv) and
[`grc/soa.xlsx`](../grc/soa.xlsx). The workbook also shows, for each control, which risks of the live service it
treats ([08](08_live_service_risk_assessment.md)).

| Theme | Implemented | Inherited | Partial | Planned | Not applicable | Total |
|---|---|---|---|---|---|---|
| 5 Organizational | 29 | 0 | 4 | 2 | 2 | 37 |
| 6 People | 3 | 0 | 0 | 0 | 5 | 8 |
| 7 Physical | 1 | 10 | 0 | 1 | 2 | 14 |
| 8 Technological | 23 | 0 | 9 | 0 | 2 | 34 |
| **All** | **56** | **10** | **13** | **3** | **11** | **93** |

The first internal audit ([07](07_internal_audit_2026-11.md)) raised one major and four minor nonconformities;
their corrective actions are tracked there.

**Treatment plan: open gaps**

| Priority | Control | Action | Due |
|---|---|---|---|
| 1 | 8.5 | Confirm two-factor authentication on Oracle | Now |
| 1 | 5.23 | Upgrade Oracle to Pay As You Go (stops idle reclamation); set a 1 EUR budget alert | Now |
| 1 | 8.1 | Bring the laptop to a supported, fully patched operating system (tracked privately) | Now |
| 2 | 7.9 | Enable disk encryption on the laptop, or record a risk acceptance | 1 month |
| 2 | 5.20 | Record which data processing agreement applies to each provider account | 1 month |
| 3 | 5.30 | Rebuild drill: recreate the VM from the repository and time it (target 1 hour) | Yearly |
| 3 | 5.35 | Independent review of this pack by a qualified peer | Yearly |
| 3 | 5.6 | Share honeypot indicators with a community feed such as AbuseIPDB | Optional |

**Closed on 2026-11-21:** admin key passphrase and agent (5.17), GitHub two-factor authentication (8.5,
GitHub part), laptop screen lock (7.7).

**Accepted risks** (documented in the SoA, reviewed quarterly): no labels on individual files (5.13), no
malware scanner while no files are stored (8.7), no leakage monitoring on the VM (8.12), no backup of the
30-day tracker data (8.13), a single honeypot VM (8.14), shared host network so the honeypot sees real source
addresses (8.22), no staging environment (8.31).

## 6. Incident management

### Playbook (A.5.24–5.28)

**Events vs incidents (A.5.25).** Attacks on the fake services are *expected events*: the honeypot exists to
receive them, and they never trigger this process. An *incident* is anything that affects the confidentiality,
integrity or availability of the service itself, or the personal data it holds.

| Severity | Meaning | Examples | Respond within |
|---|---|---|---|
| High | Compromise, or personal data exposed | Attacker reaches a real shell; raw logs or full addresses published | Immediately; GDPR breach check within 72 h |
| Medium | Service down, wrong data published, or a control missing | Tracker offline for hours; duplicated statistics; a privacy gap found | 1 day |
| Low | Degraded, nothing exposed | A build dependency fails; a cosmetic fault | 1 week |

**Steps.**
1. **Detect:** uptime check e-mail, a report through GitHub, or a finding during review.
2. **Assess:** event or incident? Severity? Is personal data involved (then GDPR Art. 33 applies)?
3. **Contain:** for High, stop the containers (`sudo docker compose down` in `/opt/honeypot`) and, if
   needed, stop the VM in the Oracle console. Collect evidence first (section 10) if the VM is still running.
4. **Fix the root cause** in the repository, test it, deploy it.
5. **Verify** with the evidence script and the live pages.
6. **Learn:** record the incident below; add a regression test where the cause can recur.

### Incident register (A.5.26, A.5.27)

All eight are real and happened during deployment and the first day of operation.

| ID | Date | Severity | What happened | Root cause | Fix | Lesson / prevention |
|---|---|---|---|---|---|---|
| INC-01 | 2026-11-20 | Low | Collector image build failed | DB-IP rejects Python's default User-Agent (HTTP 403) | Send an own User-Agent (`collector/fetch_geo.py`) | Test supplier downloads from the target network before release |
| INC-02 | 2026-11-20 | Medium | Honeypot did not start; fake SSH missing | Hardening too strict: no right to open the log; read-only `/var/tmp` for the SSH host key | `DAC_OVERRIDE` until privileges drop; tmpfs for `/var/tmp` (`docker-compose.yml`) | Verify every hardening flag on the real host; the evidence script now shows them |
| INC-03 | 2026-11-20 | Medium | Probes such as `/.env` and exploit payloads were not recorded | OpenCanary does not log unknown web paths | Log 404 requests (`opencanary/log404.tac`) | Compare raw honeypot output with what reaches the tracker |
| INC-04 | 2026-11-20 | Medium | Statistics doubled after a collector restart | The collector re-read the log from the start | Save the read position with each event in one transaction | Regression test `test_restart_resumes_from_the_saved_position` |
| INC-05 | 2026-11-20 | Low | Live feed stuck on "Connecting…" | gzip compression in Caddy buffered the event stream | Compress static files only (`Caddyfile`) | Test streaming endpoints with compression on, as browsers request it |
| INC-06 | 2026-11-20 | Medium | The operator's own test probes appeared on the public tracker | Testing against production | Deleted the test events | Test with synthetic data locally; delete self-tests immediately |
| INC-07 | 2026-11-20 | Medium | LinkedIn showed visitors "Possible malicious content" for the tracker link | The supplier domain sslip.io is distrusted | Tracker page moved to GitHub Pages; API kept on the VM with CORS for that origin only | Check a link's reputation before publishing it; plan a custom domain |
| INC-08 | 2026-11-21 | Medium | Raw honeypot log kept full addresses and about 15,500 attempted passwords with no time limit | Size-based log rotation only | Daily rotation, 7 days kept (`opencanary/opencanary.conf`) | Review raw data stores, not only what is published; retention now in the evidence snapshot |

## 7. GDPR: record of processing

IP addresses are personal data when the holder can be identified with additional information (CJEU,
C-582/14 *Breyer*). Most sources are bots or hijacked machines, but some may belong to individuals, so the
honeypot processes personal data.

**Record of processing activities (Art. 30)**

| Item | Entry |
|---|---|
| Controller | Shakthi H S (private operator of the research honeypot) |
| Purpose | Information security research and public threat statistics |
| Legal basis | Art. 6(1)(f), legitimate interests: network and information security (Recital 49) and research |
| Data subjects | Operators of systems that connect to the honeypot without being invited |
| Data | Source IP address and port, time, target service; usernames, web paths, commands and user agents the source sends; attempted passwords (raw log only); full packets of connections to the fake services (shadow mode, [09](09_shadow_mode.md)), turned into flows and deleted within the hour |
| Recipients | The public sees masked data only. Oracle hosts the VM (processor). GitHub serves static pages and receives no personal data from the service |
| Transfers outside the EU | None by the service: the VM is in Frankfurt. Masked data is public by design |
| Retention | Packet captures and flow files: deleted right after hourly scoring, never kept past 2 hours. Raw log: 7 days. Tracker database and shadow results (no addresses): 30 days. The daily hashing key is never stored |
| Security measures | The Statement of Applicability, in particular 5.34, 8.10, 8.11, 8.20, 8.24 |

**Legitimate-interest assessment (three-part test)**
1. **Purpose:** understanding real attack activity is a recognised legitimate interest (Recital 49).
2. **Necessity:** the source address is needed to count sources and to locate their country. Everything else
   is minimised: addresses lose their last part before storage, passwords never reach the tracker, sources
   are counted with a key that changes daily and is never written down.
3. **Balancing:** the data comes from unsolicited connections to a server with no legitimate use, so the
   people behind them cannot reasonably expect privacy for these connections. What is published cannot
   identify anyone, and raw data is deleted after a week. Interests do not override.

**DPIA screening (Art. 35):** no DPIA required. There is no profiling, no decision about individuals, no
special-category data, and the published data cannot identify anyone. The monitoring covers only connections
to the operator's own server, not a publicly accessible area. Revisit if raw data is ever kept longer or
shared.

**Data subject rights (Art. 11):** published records cannot be linked to a person, so the controller cannot
identify data subjects from them. Requests about raw data are answered within the 7-day raw retention.

## 8. EU AI Act and NIS2

**EU AI Act (Regulation (EU) 2024/1689): the detector**

| Question | Answer |
|---|---|
| Is it an AI system (Art. 3(1))? | Yes: a machine-learning model that infers from input how to classify network flows |
| Prohibited practice (Art. 5)? | No |
| High-risk via Annex I (product safety)? | No |
| High-risk via Annex III? | No. Annex III point 2 covers *safety components* of critical digital infrastructure, and Recital 55 states that components used solely for cybersecurity are not safety components. Annex III point 4 (employment) would apply only if the output were used to evaluate workers, which this design excludes |
| Transparency duties (Art. 50)? | No: it does not interact with people or generate content |
| Result | **Minimal risk.** Applies: AI literacy (Art. 4). Voluntary measures in place: model card (section 9), human oversight through the REVIEW band, decision logging, documented limits |

**NIS2:** the service is operated by a private individual and is not an essential or important entity, so
NIS2 does not apply. The controls above follow its risk-management measures (Art. 21) anyway: incident
handling, supply-chain security, vulnerability handling, cryptography and access control.

## 9. Model card: deployed detector

| | |
|---|---|
| Model | Gradient Boosting (known attack patterns) plus Isolation Forest trained on benign traffic only (anomalies), with three decision bands |
| Intended use | Prioritising network flows for a SOC analyst: ALERT (score ≥ 0.7), REVIEW (0.2–0.7 or anomalous), ALLOW |
| Not intended for | Blocking traffic automatically; judging individuals; use without an analyst reviewing the REVIEW band |
| Training data | CIC-IDS2017 with corrected labels (KU Leuven DistriNet), 833,240 flows from 70% of Monday–Wednesday, 82 flow features; addresses, ports and times removed |
| Test data | 1,266,736 flows the model never trained on, including 8 attack types absent from training |
| Results | Known attack types: 99.99% detected. Unseen attack types: 70.9% detected, all through the REVIEW band. Benign flows sent to review: 5.1% |
| Known weaknesses | DDoS 1.6%, botnet 6.0%, web brute force 0% and SQL injection 7.7% detected when unseen; password guessing is invisible at flow level; simple traffic padding evades part of the detections (`results/guardrails_evasion.csv`) |
| Oversight | Every REVIEW decision goes to a human; the browser and server versions must agree on all 17,353 replay flows before release |
| Source | [`live/model/card.json`](../live/model/card.json), [`app/train.py`](../app/train.py) |

## 10. Evidence and how to refresh it

| Evidence | What it proves |
|---|---|
| [`grc/evidence/vm-2026-11-21.txt`](../grc/evidence/vm-2026-11-21.txt) | Firewall rules, SSH settings, container hardening, time sync, TLS certificate, log retention, as found on the VM |
| [`grc/soa.csv`](../grc/soa.csv) | Status, justification and evidence for every Annex A control |
| [`tests/test_soa.py`](../tests/test_soa.py) | Every evidence file named in the SoA exists; the summary above matches the SoA |
| [`.github/workflows/uptime.yml`](../.github/workflows/uptime.yml) | Monitoring every 30 minutes, with e-mail on failure |
| [`tests/test_honeypot.py`](../tests/test_honeypot.py) | Privacy, hostile input, retention and firewall rules are tested on every push |
| [`grc/evidence/github-ruleset-protect-main.json`](../grc/evidence/github-ruleset-protect-main.json) | `main` cannot be deleted or force-pushed; changes need a pull request that passes the CI `test` check |
| [`grc/evidence/github-repo-security-2026-11-21.json`](../grc/evidence/github-repo-security-2026-11-21.json) | Secret scanning, push protection, Dependabot alerts and security updates, private vulnerability reporting: all on |
| [`.github/workflows/container.yml`](../.github/workflows/container.yml) | Every update is built and smoke-tested before it merges, the honeypot images included |
| [`grc/audit_tests.sh`](../grc/audit_tests.sh), [`grc/evidence/audit-tests-2026-11-21.txt`](../grc/evidence/audit-tests-2026-11-21.txt) | 25 audit tests re-performing sampled controls from outside the system, and their results |

**Refresh (quarterly and after changes):** copy `grc/collect_evidence.sh` to the VM, run
`sudo bash collect_evidence.sh > vm-$(date -u +%F).txt`, commit the output under `grc/evidence/`, and point
the SoA at the new file.
