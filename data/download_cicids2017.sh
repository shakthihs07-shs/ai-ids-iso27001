#!/usr/bin/env bash
# Downloads CIC-IDS2017 with corrected labels (328 MB zip, 1.1 GB unpacked) into data/cicids2017/.
# Source: Engelen et al., KU Leuven DistriNet, https://intrusion-detection.distrinet-research.be/CNS2022/
# Original dataset: Canadian Institute for Cybersecurity, https://www.unb.ca/cic/datasets/ids-2017.html
set -euo pipefail
mkdir -p "$(dirname "$0")/cicids2017" && cd "$(dirname "$0")/cicids2017"
curl -sSfL -o CICIDS2017_improved.zip https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip
SUMS="97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883  CICIDS2017_improved.zip"
if command -v sha256sum >/dev/null; then CHECK="sha256sum"; else CHECK="shasum -a 256"; fi
echo "$SUMS" | $CHECK -c --quiet - || { rm -f CICIDS2017_improved.zip; echo "Checksum mismatch: download removed" >&2; exit 1; }
unzip -o -q CICIDS2017_improved.zip && rm CICIDS2017_improved.zip
echo "Unpacked: $(ls *.csv | tr '\n' ' ')"
