# Live attack tracker (honeypot)

An internet-facing honeypot on an Oracle Cloud Always Free VM, and a public page that shows every
attack on it as it happens, mapped to MITRE ATT&CK.

- `opencanary/`: [OpenCanary](https://github.com/thinkst/opencanary) low-interaction honeypot with 12 fake
  services (SSH, Telnet, FTP, web login, MySQL, MSSQL, Redis, MongoDB, RDP, VNC, Git, HTTP proxy).
  No attacker can get a shell: the services only imitate real ones.
- `collector/`: reads OpenCanary's log, maps each event to an ATT&CK technique, and stores it privacy-safe
  (country, address without its last part, a daily-keyed hash for counting; never full IPs or passwords;
  30-day retention). Serves `/api/events`, `/api/stats` and a live `/api/stream`.
- `site/`: the tracker page. Attacker-supplied text is escaped and the CSP forbids inline script.
- `Caddyfile`: HTTPS on a free `<ip>.sslip.io` name; port 80 stays with the honeypot's web login.
- `setup-host.sh`: one-time VM setup. Admin SSH moves to port 22022 (key only), the host firewall opens
  only the fake services and 443.

Deploy (from this folder on the VM): `sudo bash setup-host.sh firewall`, check `ssh -p 22022` works,
then `sudo bash setup-host.sh start <public-ip>`.
