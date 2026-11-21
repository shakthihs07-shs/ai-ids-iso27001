#!/usr/bin/env bash
# One-time setup of the honeypot VM (Ubuntu 24.04 on Oracle Cloud), run as root from this folder:
#   sudo bash setup-host.sh firewall      # firewall + move admin SSH to ADMIN_PORT (keep this session open)
#   sudo bash setup-host.sh start <ip>    # after `ssh -p ADMIN_PORT` works: start honeypot, collector, HTTPS
#   sudo bash setup-host.sh shadow        # (included in start) shadow mode: capture, flow tool, hourly scoring
set -euo pipefail
ADMIN_PORT=22022
# Fake services (opencanary/opencanary.conf) + 443 for the tracker page. tests/test_honeypot.py keeps them in sync.
PUBLIC_PORTS="21,22,23,80,443,1433,3306,3389,5900,6379,8080,9418,27017"

firewall() {
  # The Always Free E2.1.Micro has 1 GB of RAM: too little for apt and Docker image builds without swap
  if [ ! -e /swapfile ] && [ "$(awk '/MemTotal/ {print $2}' /proc/meminfo)" -lt 2000000 ]; then
    fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
  DEBIAN_FRONTEND=noninteractive apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2 iptables-persistent unattended-upgrades
  systemctl enable --now docker unattended-upgrades

  # Oracle's image rejects all input except SSH on 22. Accept admin SSH and the public ports, before that REJECT.
  iptables -C INPUT -p tcp --dport "$ADMIN_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$ADMIN_PORT" -j ACCEPT
  iptables -C INPUT -p tcp -m multiport --dports "$PUBLIC_PORTS" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 2 -p tcp -m multiport --dports "$PUBLIC_PORTS" -j ACCEPT
  netfilter-persistent save

  # Admin SSH: key only, no root, on ADMIN_PORT; port 22 is left for the honeypot.
  cat > /etc/ssh/sshd_config.d/10-admin.conf <<CONF
Port $ADMIN_PORT
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
CONF
  mkdir -p /etc/systemd/system/ssh.socket.d   # Ubuntu 24.04 starts sshd from ssh.socket
  printf '[Socket]\nListenStream=\nListenStream=%s\n' "$ADMIN_PORT" > /etc/systemd/system/ssh.socket.d/10-admin.conf
  sshd -t
  systemctl daemon-reload
  systemctl restart ssh.socket
  echo "Admin SSH now listens on $ADMIN_PORT. Test it in a new connection before running: setup-host.sh start <ip>"
}

start() {
  local ip=${1:?public IP address}
  echo "TRACKER_HOST=${ip//./-}.sslip.io" > .env
  ss -ltn | grep -q ":22 " && { echo "something still listens on port 22; run 'firewall' first" >&2; exit 1; }
  docker compose up -d --build
  # Refresh the country database monthly by rebuilding the collector
  printf '#!/bin/sh\ncd %s && docker compose build collector && docker compose up -d collector\n' "$PWD" > /etc/cron.monthly/honeypot-geo
  chmod +x /etc/cron.monthly/honeypot-geo
  shadow
  echo "Tracker: https://${ip//./-}.sslip.io/"
}

shadow() {  # shadow mode (docs/09): capture runs with the stack; flows are made and scored at minute 5 of every hour
  docker compose up -d --build capture
  docker compose --profile jobs build
  printf '5 * * * * root sh %s/shadow/run-hourly.sh >> /var/log/honeypot-shadow.log 2>&1\n' "$PWD" > /etc/cron.d/honeypot-shadow
}

"$@"
