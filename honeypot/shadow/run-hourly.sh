#!/bin/sh
# Shadow mode, hourly: turn each finished capture into flows with the fixed CICFlowMeter, score them, then delete
# the capture and the flows, which hold full packets and addresses. Installed as a cron job by setup-host.sh.
# The flow tool bundles a Log4Shell-era log4j, so it runs without network, read-only, with no capabilities;
# its log files (which can contain addresses) go to memory and disappear with the container.
set -u
cd "$(dirname "$0")/.."
PCAP=$(docker volume inspect -f '{{.Mountpoint}}' honeypot_shadow-pcap) || exit 1
KEEP=1; [ "${ALL:-0}" = 1 ] && KEEP=0  # ALL=1 also takes the newest file: only once the capture has stopped (CI)
for f in $(ls "$PCAP"/*.pcap 2>/dev/null | sort | head -n -$KEEP); do  # skip the newest: tcpdump still writes it
  work=$(mktemp -d) && chmod 711 "$work" && mkdir -m 755 "$work/in" "$work/out" && mv "$f" "$work/in/" || continue
  docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /opt/cfm/bin/logs --cap-drop ALL \
    --security-opt no-new-privileges --memory 768m -v "$work/in:/in:ro" -v "$work/out:/out" \
    honeypot-cicflowmeter /in /out > /dev/null 2>&1
  echo "$(basename "$f"): $(cat "$work"/out/*.csv 2>/dev/null | wc -l) flow lines"  # a count only, never addresses
  chmod -R a+rX "$work/out"
  docker compose --profile jobs run --rm -T -v "$work/out:/flows:ro" shadow /flows
  rm -rf "$work"
done
find "$PCAP" -name '*.pcap' -mmin +120 -delete  # never keep a capture past 2 hours, even if processing failed
