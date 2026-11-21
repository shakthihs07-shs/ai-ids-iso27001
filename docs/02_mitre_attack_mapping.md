# 02 – MITRE ATT&CK Mapping and Detection Coverage

Each of the 37 attack types in the NSL-KDD test set was mapped to the closest MITRE ATT&CK (Enterprise) technique based on what the attack does. Detection rate = share of that attack's test records flagged by the ensemble at threshold 0.5. Full per-attack table: `results/mitre_coverage.csv`. Script: `src/mitre_mapping.py`.

> Mapping note: NSL-KDD attacks date from the late 1990s, so the mapping is to the closest modern technique. It is analyst judgement, not an official MITRE mapping.

## Coverage by technique

| Coverage | Tactic | Technique | NSL-KDD attacks | Test records | Detected |
|---|---|---|---|---|---|
| **Good** | Impact | T1499.001 OS Exhaustion Flood | neptune (SYN flood) | 4,657 | **100%** |
| **Good** | Impact | T1498.002 Reflection Amplification | smurf | 665 | **100%** |
| **Good** | Impact | T1498.001 Direct Network Flood | udpstorm | 2 | 100% |
| **Good** | Discovery | T1018 Remote System Discovery | ipsweep | 141 | **100%** |
| **Good** | Discovery | T1046 Network Service Discovery | nmap, portsweep | 230 | **100%** |
| **Good** | Impact | T1499.004 Application or System Exploitation | pod, teardrop, land | 60 | 93% |
| Partial | Reconnaissance | T1595.002 Vulnerability Scanning | satan, saint, mscan | 2,050 | 75% |
| Partial | Impact | T1499.003 Application Exhaustion Flood | back, apache2, mailbomb | 1,389 | 69% |
| **Gap** | Privilege Escalation | T1068 Exploitation for Privilege Escalation | buffer_overflow, perl, ps, xterm, loadmodule | 52 | 29% |
| **Gap** | Initial Access | T1078.001 Default Accounts | snmpgetattack, warezmaster | 1,122 | 23% |
| **Gap** | Initial Access | T1190 Exploit Public-Facing Application | imap, phf, named, sendmail, sqlattack | 36 | 14% |
| **Gap** | Impact | T1499.002 Service Exhaustion Flood | processtable | 685 | 7% |
| **Gap** | Lateral Movement | T1021 Remote Services | multihop | 18 | 6% |
| **Gap** | Command and Control | T1572 Protocol Tunneling | httptunnel | 133 | 3% |
| **Gap** | Credential Access | T1110.001 Password Guessing | guess_passwd, snmpguess | 1,562 | **0%** |
| **Gap** | Defense Evasion | T1014 Rootkit | rootkit | 13 | 0% |

Coverage bands: Good ≥ 80%, Partial 40–80%, Gap < 40%. Also in the CSV, all Gap: T1056.002 GUI Input Capture (xlock, 9 records, 0%), T1056.001 Keylogging (xsnoop, 4), T1105 Ingress Tool Transfer (ftp_write, 3), T1210 Exploitation of Remote Services (worm, 2).

## What this tells a security manager

1. **Volume-based attacks are solved by flow ML.** Floods and scans change traffic statistics (connection counts, error rates), which is exactly what the 41 NSL-KDD features measure.
2. **Content- and identity-based attacks are invisible to flow ML.** Password guessing, default-community SNMP access, exploits and privilege escalation look like normal connections at the flow level. `guess_passwd` had only **53 training examples**, and the test set adds attack types never seen in training.
3. **Compensating controls must come from other layers**, not from tuning the model:
   - T1110 / T1078 → **MFA, account lockout, failed-login alerting, removal of default credentials/SNMP community strings** (ISO 27001 controls 5.17, 8.5)
   - T1068 / T1014 → **EDR, patching, least privilege** (8.7, 8.8, 8.2)
   - T1190 → **WAF, vulnerability management, secure configuration** (8.8, 8.9, 8.20)
   - T1572 → **egress filtering, proxy inspection, DNS/HTTP analytics** (8.20, 8.22, 8.23)

These gaps feed risks R02 and R03 in the risk register.
