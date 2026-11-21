#!/usr/bin/env bash
# Prints the honeypot VM's security configuration as audit evidence (ISO/IEC 27001 Annex A references in
# brackets). Run on the VM as root:  sudo bash collect_evidence.sh > vm-$(date -u +%F).txt
# Read-only. Prints no secrets: no keys, no log contents, no attacker data.
set -uo pipefail
cd /opt/honeypot
section() { printf '\n## %s\n' "$*"; }

echo "# Honeypot VM evidence snapshot, $(date -u '+%F %T UTC')"
section "Host [A.8.8, A.8.9]"
. /etc/os-release && echo "OS: $PRETTY_NAME, kernel $(uname -r)"
echo "unattended-upgrades: $(systemctl is-active unattended-upgrades)"
echo "last package update: $(stat -c %y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || echo unknown)"

section "Host firewall, input chain [A.8.20, A.8.22]"
iptables -S INPUT

section "Admin SSH, effective settings [A.8.2, A.8.5]"
sshd -T 2>/dev/null | grep -E '^(port|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication) '
systemctl show ssh.socket -p Listen

section "Listening ports [A.8.20]"
ss -ltnH | awk '{print $4}' | sed 's/.*://' | sort -n | uniq | tr '\n' ' '; echo

section "Containers: hardening [A.8.9, A.8.19]"
for c in $(docker compose ps -q); do
  docker inspect "$c" --format '{{.Name}}: image={{.Config.Image}} user={{if .Config.User}}{{.Config.User}}{{else}}image default{{end}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} cap_add={{.HostConfig.CapAdd}} no_new_privileges={{.HostConfig.SecurityOpt}} memory={{.HostConfig.Memory}}'
done
echo "OpenCanary runs as: $(ps -o user= -C twistd | sort -u | tr '\n' ' ')"

section "Clock synchronisation [A.8.17]"
timedatectl show -p NTPSynchronized -p NTP

section "TLS certificate of the tracker API [A.8.24]"
host=$(sed -n 's/^TRACKER_HOST=//p' .env)
echo | openssl s_client -connect 127.0.0.1:443 -servername "$host" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates

section "Log retention [A.5.34, A.8.10]"
echo "raw honeypot logs (rotated daily, 7 days kept):"
ls -l --time-style=+%F /var/lib/docker/volumes/honeypot_canary-logs/_data/ | tail -n +2 | awk '{print "  " $6, $5, $7}'
docker compose exec -T collector python -c "
import sqlite3; con = sqlite3.connect('/data/tracker.db')
print('tracker database: %d events, oldest %s, newest %s' % con.execute('SELECT COUNT(*), MIN(ts), MAX(ts) FROM events').fetchone())"
