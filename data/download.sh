#!/usr/bin/env bash
# Downloads NSL-KDD (KDDTrain+.txt, KDDTest+.txt) into this folder.
# Original source: Canadian Institute for Cybersecurity, https://www.unb.ca/cic/datasets/nsl.html
set -euo pipefail
cd "$(dirname "$0")"
BASE=https://raw.githubusercontent.com/defcom17/NSL_KDD/master
curl -sSfL -o KDDTrain+.txt "$BASE/KDDTrain+.txt"
curl -sSfL -o KDDTest+.txt "$BASE/KDDTest+.txt"
# Fail if the mirror's files ever change (see risk R09: hash training data)
SUMS="1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95  KDDTrain+.txt
fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84  KDDTest+.txt"
if command -v sha256sum >/dev/null; then CHECK="sha256sum"; else CHECK="shasum -a 256"; fi
echo "$SUMS" | $CHECK -c --quiet - || { rm -f KDDTrain+.txt KDDTest+.txt; echo "Checksum mismatch: downloaded files removed" >&2; exit 1; }
echo "Downloaded: $(wc -l < KDDTrain+.txt) training rows, $(wc -l < KDDTest+.txt) test rows"
