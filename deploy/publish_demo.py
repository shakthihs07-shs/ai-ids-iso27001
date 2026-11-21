"""Copy the public demo (results dashboard, live console, attack tracker) into a checkout of the ids-demo repo.

    python deploy/publish_demo.py ../ids-demo      then commit and push in ../ids-demo

The demo keeps its own repository so its URLs, already shared, stay stable. Only the pages and the data
files they read are published there.
"""
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = "https://shakthihs07-shs.github.io/ids-demo/"
CODE = "https://github.com/shakthihs07-shs/ai-ids-iso27001"
TRACKER_API = "https://152-70-6-78.sslip.io/"  # the honeypot VM; LinkedIn flags sslip.io links, so the page lives here

README = f"""# AI intrusion detection: live demo

- **[Live IDS console]({SITE}live/)**: network flows scored in real time, in your browser, by a hybrid
  detector (Gradient Boosting for known attacks, Isolation Forest for attack types it never saw), with an
  analyst review queue.
- **[Live attack tracker]({SITE}tracker/)**: real attacks on an internet-facing honeypot
  (OpenCanary on Oracle Cloud) as they happen: login attempts, scans and exploit payloads, mapped to
  MITRE ATT&CK, with IP addresses truncated and passwords never stored.
- **[Results dashboard]({SITE})**: model comparison on NSL-KDD and CIC-IDS2017, novel-attack detection,
  MITRE ATT&CK coverage, alert-threshold trade-off, drift, and an ISO/IEC 27001:2022 risk register.

The detector runs client-side as ONNX models in onnxruntime-web. This repository holds only the published
pages and the data they read; the source code, research, honeypot and risk assessment are in
**[{CODE.split("/", 3)[3]}]({CODE})**.

Data: CIC-IDS2017 (Sharafaldin, Habibi Lashkari and Ghorbani, ICISSP 2018), labels corrected by
Engelen, Rimmer and Joosen (KU Leuven, WTMC 2021) and Liu et al. (CNS 2022); NSL-KDD (Tavallaee et al.,
CISDA 2009). `live/replay.csv.gz` is a sample of 17,353 CIC-IDS2017 test flows.

Author: Shakthi H S, MSc Cybersecurity (IU Berlin).
"""


def publish(target: Path):
    if not (target / ".git").is_dir():
        sys.exit(f"{target} is not a git checkout of the demo repository")
    for p in target.iterdir():  # start clean so files removed here disappear there too
        if p.name != ".git":
            shutil.rmtree(p) if p.is_dir() else p.unlink()

    page = (ROOT / "index.html").read_text(encoding="utf-8")
    results = re.search(r"const files = \[(.*?)\];", page, re.S).group(1)
    files = ["risk_register.csv", "risk_register.xlsx"] + [f"results/{f}.csv" for f in re.findall(r'"([^"]+)"', results)]
    for f in files:
        (target / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f, target / f)
    shutil.copytree(ROOT / "live", target / "live")
    (target / "index.html").write_text(page, encoding="utf-8")
    # The live attack tracker page, reading the honeypot's API. GitHub Pages sends no CSP header, so the page
    # carries its own: it shows attacker-supplied text, and must load scripts only from here.
    (target / "tracker").mkdir()
    shutil.copy(ROOT / "honeypot" / "site" / "tracker.js", target / "tracker" / "tracker.js")
    csp = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
           f"connect-src {TRACKER_API.rstrip('/')}; base-uri 'none'; form-action 'none'")
    head = (f'<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
            f'<meta name="tracker-api" content="{TRACKER_API}">')
    tracker = (ROOT / "honeypot" / "site" / "index.html").read_text(encoding="utf-8")
    assert tracker.count('<meta charset="utf-8">') == 1
    (target / "tracker" / "index.html").write_text(tracker.replace('<meta charset="utf-8">', head), encoding="utf-8")
    (target / ".nojekyll").write_text("")
    (target / "README.md").write_text(README, encoding="utf-8")
    print(f"published {len(files) + 3} files and live/ to {target}")


if __name__ == "__main__":
    publish(Path(sys.argv[1]).resolve())
