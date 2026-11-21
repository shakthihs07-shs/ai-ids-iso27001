#!/bin/sh
# Capture full packets of connections to the honeypot's fake services into one file per hour.
# Only packets to or from this server's own address on those ports: not the tracker (443), not admin SSH (22022),
# not the server's own outgoing traffic such as updates. The ports must match opencanary.conf (a test checks it).
set -eu
PORTS="21 22 23 80 1433 3306 3389 5900 6379 8080 9418 27017"
# The interface that faces the internet (a real interface, not "any": the flow tool needs Ethernet frames)
IFACE=${IFACE:-$(ip -o route get 1.1.1.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p')}
LOCAL=$(ip -o -4 addr show dev "$IFACE" | sed -n 's/.* inet \([0-9.]*\).*/\1/p' | head -1)
ports() { for p in $PORTS; do printf '%s port %s or ' "$1" "$p"; done | sed 's/ or $//'; }
FILTER="tcp and ((dst host $LOCAL and ($(ports dst))) or (src host $LOCAL and ($(ports src))))"
echo "capturing on $IFACE: $FILTER"
exec tcpdump -i "$IFACE" -nn -s 0 -Z tcpdump -G 3600 -w '/pcap/%Y%m%d-%H%M.pcap' "$FILTER"
