# Security policy

## Reporting a vulnerability

Please report security issues in this repository, the live IDS console or the live attack tracker through
GitHub's private reporting: **Security → Report a vulnerability** on this repository. Do not open a public
issue for a vulnerability.

You can expect an acknowledgement within 7 days and a fix or a decision within 30 days. Reports are handled
as security events under the incident process in [docs/06_grc_evidence_pack.md](docs/06_grc_evidence_pack.md).

## Scope

- In scope: the code in this repository, the demo pages on `shakthihs07-shs.github.io/ids-demo`, and the
  tracker API.
- Out of scope: the honeypot's fake services (ports 21, 22, 23, 80, 1433, 3306, 3389, 5900, 6379, 8080,
  9418, 27017). They exist to be attacked, so connecting to them is not a finding, and everything sent to
  them is logged.
