"""Map every NSL-KDD attack type to MITRE ATT&CK and measure detection per technique.

Mapping is analyst judgement based on what each attack does (see docs/02_mitre_attack_mapping.md).
Output: results/mitre_coverage.csv (per attack type) and results/mitre_by_technique.csv
"""
from pathlib import Path

import joblib
import pandas as pd

from common import ensemble_score, load, feature_cols

OUT = Path(__file__).resolve().parent.parent / "results"

# attack -> (tactic, technique id, technique name, what the attack does)
MITRE = {
    "neptune": ("Impact", "T1499.001", "Endpoint DoS: OS Exhaustion Flood", "TCP SYN flood"),
    "smurf": ("Impact", "T1498.002", "Network DoS: Reflection Amplification", "ICMP echo to broadcast, spoofed source"),
    "pod": ("Impact", "T1499.004", "Endpoint DoS: Application or System Exploitation", "Ping of death (oversized ICMP)"),
    "teardrop": ("Impact", "T1499.004", "Endpoint DoS: Application or System Exploitation", "Overlapping IP fragments"),
    "land": ("Impact", "T1499.004", "Endpoint DoS: Application or System Exploitation", "SYN with source = destination"),
    "back": ("Impact", "T1499.003", "Endpoint DoS: Application Exhaustion Flood", "Apache request with thousands of slashes"),
    "apache2": ("Impact", "T1499.003", "Endpoint DoS: Application Exhaustion Flood", "Apache request with many headers"),
    "mailbomb": ("Impact", "T1499.003", "Endpoint DoS: Application Exhaustion Flood", "Mass mail to one SMTP server"),
    "processtable": ("Impact", "T1499.002", "Endpoint DoS: Service Exhaustion Flood", "Exhausts server process table"),
    "udpstorm": ("Impact", "T1498.001", "Network DoS: Direct Network Flood", "UDP echo/chargen loop"),
    "ipsweep": ("Discovery", "T1018", "Remote System Discovery", "Ping sweep for live hosts"),
    "nmap": ("Discovery", "T1046", "Network Service Discovery", "Port scanning"),
    "portsweep": ("Discovery", "T1046", "Network Service Discovery", "Port sweep across hosts"),
    "satan": ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning", "SATAN vulnerability scanner"),
    "saint": ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning", "SAINT vulnerability scanner"),
    "mscan": ("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning", "Multi-vulnerability scanner"),
    "guess_passwd": ("Credential Access", "T1110.001", "Brute Force: Password Guessing", "Telnet/POP password guessing"),
    "snmpguess": ("Credential Access", "T1110.001", "Brute Force: Password Guessing", "Guessing SNMP community strings"),
    "snmpgetattack": ("Initial Access", "T1078.001", "Valid Accounts: Default Accounts", "SNMP access with default community string"),
    "warezmaster": ("Initial Access", "T1078.001", "Valid Accounts: Default Accounts", "Upload to writable anonymous FTP"),
    "warezclient": ("Command and Control", "T1105", "Ingress Tool Transfer", "Download from anonymous FTP"),
    "ftp_write": ("Persistence", "T1105", "Ingress Tool Transfer", "Writes files via misconfigured FTP"),
    "imap": ("Initial Access", "T1190", "Exploit Public-Facing Application", "IMAP buffer overflow"),
    "phf": ("Initial Access", "T1190", "Exploit Public-Facing Application", "Vulnerable phf CGI script"),
    "named": ("Initial Access", "T1190", "Exploit Public-Facing Application", "DNS server (BIND) overflow"),
    "sendmail": ("Initial Access", "T1190", "Exploit Public-Facing Application", "Sendmail overflow"),
    "multihop": ("Lateral Movement", "T1021", "Remote Services", "Hops across hosts via remote logins"),
    "worm": ("Lateral Movement", "T1210", "Exploitation of Remote Services", "Self-propagating worm"),
    "spy": ("Collection", "T1040", "Network Sniffing", "Long-term covert monitoring"),
    "xsnoop": ("Collection", "T1056.001", "Input Capture: Keylogging", "Captures X11 keystrokes"),
    "xlock": ("Credential Access", "T1056.002", "Input Capture: GUI Input Capture", "Fake X screensaver steals password"),
    "buffer_overflow": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "Local overflow to root"),
    "loadmodule": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "loadmodule SUID bug"),
    "perl": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "suidperl bug"),
    "ps": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "ps race condition"),
    "xterm": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "xterm overflow"),
    "rootkit": ("Defense Evasion", "T1014", "Rootkit", "Installs rootkit after root"),
    "sqlattack": ("Initial Access", "T1190", "Exploit Public-Facing Application", "SQL injection"),
    "httptunnel": ("Command and Control", "T1572", "Protocol Tunneling", "Tunnels traffic over HTTP"),
}


def main():
    train, test, unseen = load()
    bundle = joblib.load(OUT / "models.joblib")
    score = ensemble_score(bundle["models"], test[feature_cols()])
    test = test.assign(detected=score >= 0.5)
    att = test[test.is_attack == 1]
    per = att.groupby("label").agg(test_rows=("detected", "size"), detected=("detected", "sum")).reset_index()
    per["recall"] = per.detected / per.test_rows
    per["in_training_data"] = ~per.label.isin(unseen)
    per["category"] = per.label.map(dict(zip(test.label, test.category)))
    for i, col in enumerate(["tactic", "technique_id", "technique", "behaviour"]):
        per[col] = per.label.map(lambda x: MITRE[x][i])
    missing = set(per.label) - set(MITRE)
    assert not missing, missing
    per = per.sort_values(["tactic", "technique_id", "label"])
    per.to_csv(OUT / "mitre_coverage.csv", index=False, float_format="%.6f")

    tech = per.groupby(["tactic", "technique_id", "technique"]).agg(
        attack_types=("label", lambda s: ", ".join(s)), test_rows=("test_rows", "sum"),
        detected=("detected", "sum")).reset_index()
    tech["recall"] = tech.detected / tech.test_rows
    tech["coverage"] = pd.cut(tech.recall, [-0.01, 0.4, 0.8, 1.01], labels=["Gap", "Partial", "Good"])
    tech = tech.sort_values("recall")
    tech.to_csv(OUT / "mitre_by_technique.csv", index=False, float_format="%.6f")
    pd.set_option("display.width", 200)
    print(tech[["tactic", "technique_id", "technique", "test_rows", "recall", "coverage"]].to_string(index=False))


if __name__ == "__main__":
    main()
