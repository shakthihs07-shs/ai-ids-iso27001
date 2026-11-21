# 09 – Shadow mode: the detector against real attacks

**Question:** a detector trained on 2017 lab traffic (CIC-IDS2017) scored 99.99% on known attack types and 70.9% on
unseen ones in testing. How much of the real traffic hitting an internet-facing server in 2026 would it flag?

**Shadow mode** means the detector sees real traffic and records what it *would* decide, but decides nothing:
the honeypot keeps answering every connection, and no traffic is blocked.

## 1. How it works

```
attackers ──► fake services (OpenCanary)
                 │  full packets, honeypot ports only
                 ▼
         capture (tcpdump) ── one file per hour ──► fixed CICFlowMeter (KU Leuven DistriNet)
                                                         │  82 flow features per connection
                                                         ▼
                                    detector: Gradient Boosting + Isolation Forest (ONNX)
                                                         │  ALERT / REVIEW / ALLOW
                                                         ▼
                          tracker database (time, service, size, scores, decision; no address)
                                                         ▼
                             tracker card "What the AI says about these real attacks"
```

- **Same features as in training.** The flows are computed by the fixed CICFlowMeter that produced the corrected
  CIC-IDS2017 dataset, built from the authors' source at a pinned commit
  ([`honeypot/shadow/cicflowmeter.Dockerfile`](../honeypot/shadow/cicflowmeter.Dockerfile)). One column is renamed
  to the dataset's name (`Total Connection Flow Time` → `Total TCP Flow Time`); the scorer refuses a flow file that
  lacks any of the 82 features.
- **Same model and rules as the live console.** The published ONNX models, the signed-log transform and the
  ALERT ≥ 0.7 / REVIEW 0.2–0.7 or anomalous / ALLOW bands ([`honeypot/shadow/score.py`](../honeypot/shadow/score.py)).
- **Hourly.** At minute 5, [`run-hourly.sh`](../honeypot/shadow/run-hourly.sh) processes every finished capture.
- **Tested end to end.** CI builds the flow tool, captures test traffic to the honeypot, and checks that flows are
  scored, served by the API and that captures are deleted ([`container.yml`](../.github/workflows/container.yml)).

## 2. Privacy and security

| Concern | Control |
|---|---|
| Full packets include what attackers send, such as passwords typed into the fake Telnet | Captured only on the honeypot ports and only to or from this server: never the tracker (443), admin SSH (22022) or the server's own outgoing traffic. Captures are deleted right after the hourly run, and never kept past 2 hours even if a run fails. They stay on the server in the EU, readable by root only |
| Flow files contain addresses | Created in a private temporary folder for each run and deleted right after scoring |
| What is kept | Per flow: time, service, port, packet count, duration, scores, decision. No address of any kind, so the stored results are not personal data |
| The flow tool bundles log4j 2.11 (Log4Shell) and a native packet parser, and reads attacker packets | Runs with no network (the exploit needs an outbound connection), log4j message lookups disabled, read-only, no capabilities, memory-limited; its log files are kept in memory only. Risk LR13 in [08](08_live_service_risk_assessment.md) |

The GDPR record of processing in [06 §7](06_grc_evidence_pack.md#7-gdpr-record-of-processing) covers the packet
captures.

## 3. How to read the results

- **Every flow is an attack or a scan.** Nobody has a reason to connect to the honeypot, so the share the detector
  flags is its detection rate on real attacks, and ALLOW means a miss.
- **No false-positive rate.** There is no benign traffic to measure false alarms against; that stays the
  lab figure (5.1%).
- **A flow is not an event.** One SSH brute-force session may be several flows; the tracker's event counts and the
  flow counts differ.

## 4. Known limits

- **The honeypot's answers are not a real server's.** OpenCanary imitates services, so sessions are shorter and
  replies smaller than with real software. Part of any difference to the lab result is caused by the honeypot,
  not by the attackers.
- **Tool version.** The pinned commit is the authors' current fixed version; the corrected dataset may have been
  produced with an earlier revision. Feature definitions are the same family, but small differences are possible.
- **Flow-level blind spots stay.** Password guessing looks like normal logins at flow level (0% in the lab), and
  much of the honeypot's traffic is exactly that.
- **Single location.** One server in one cloud region sees one slice of the internet.

## 5. Results

To be added after the first full week (planned 2026-11-28): flagged share overall and per service, compared with
the lab results, with the limits above.
