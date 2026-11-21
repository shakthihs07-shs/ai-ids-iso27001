#!/usr/bin/env bash
# Internal audit tests: re-performs sampled ISO/IEC 27001 Annex A controls against the live service from the
# outside, the way an auditor would, and prints PASS / FAIL per test with the control it samples.
#   bash grc/audit_tests.sh > grc/evidence/audit-tests-$(date -u +%F).txt
# Read-only. Needs bash, curl, openssl, ssh and python3 (or python). Uses only public GitHub APIs.
set -uo pipefail
API=https://152-70-6-78.sslip.io            # tracker API on the honeypot VM
HOST=152.70.6.78
SITE=https://shakthihs07-shs.github.io/ids-demo
REPO=https://api.github.com/repos/shakthihs07-shs/ai-ids-iso27001
PY=$(command -v python3 || command -v python)
fails=0
check() {  # check <control> <description> <command...>: PASS if the command succeeds
  local control=$1 what=$2; shift 2
  if out=$("$@" 2>&1); then echo "PASS [$control] $what${out:+ ($out)}"; else echo "FAIL [$control] $what${out:+ ($out)}"; fails=$((fails + 1)); fi
}
port_open() { timeout 4 bash -c "</dev/tcp/$HOST/$1" 2>/dev/null; }
json() { "$PY" -c "import json,sys; d=json.load(sys.stdin); $1"; }

echo "# Internal audit tests, $(date -u '+%F %T UTC')"

# A.8.20 network security: the fake services, HTTPS and admin SSH answer; nothing else does
for p in 22 80 443 22022; do check A.8.20 "port $p reachable (expected)" port_open "$p"; done
for p in 111 2375 3000 5432 8000 9000; do check A.8.20 "port $p not reachable (collector API, Docker API, others)" bash -c "! timeout 4 bash -c '</dev/tcp/$HOST/$p' 2>/dev/null"; done

# A.8.5 / A.5.17 secure authentication: admin SSH refuses passwords and root
key_only() {  # the server offers no method but publickey to this user, so a password can never be tried
  local r; r=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
    -o PubkeyAuthentication=no -p 22022 "$1@$HOST" true 2>&1 | grep -o 'Permission denied ([^)]*)')
  echo "$r"; [ "$r" = 'Permission denied (publickey)' ]
}
check A.8.5 "admin SSH offers public-key login only" key_only auditor
check A.8.2 "root gets no password login over SSH" key_only root

# A.8.24 cryptography: valid certificate with time left, old TLS versions refused
check A.8.24 "certificate valid and trusted, more than 14 days left" bash -c "curl -sfo /dev/null $API/api/health && echo | openssl s_client -connect $HOST:443 -servername ${API#https://} 2>/dev/null | openssl x509 -noout -checkend 1209600 -enddate"
check A.8.24 "TLS 1.0 and 1.1 refused" bash -c "! curl -s -o /dev/null --tlsv1.0 --tls-max 1.1 $API/api/health"

# A.8.21 network services: security headers, CORS only for the demo site
check A.8.21 "HSTS and CSP sent by the tracker server" bash -c "h=\$(curl -sI $API/); grep -qi '^strict-transport-security' <<< \"\$h\" && grep -qi \"^content-security-policy: default-src 'self'\" <<< \"\$h\""
check A.8.21 "API grants cross-origin access to the demo site" bash -c "curl -sI -H 'Origin: https://shakthihs07-shs.github.io' $API/api/stats | grep -qi '^access-control-allow-origin: https://shakthihs07-shs.github.io'"
check A.8.21 "API does not grant cross-origin access to other sites" bash -c "! curl -sI -H 'Origin: https://evil.example' $API/api/stats | grep -qi 'evil.example'"
check A.8.21 "public tracker page carries its own CSP" bash -c "curl -s $SITE/tracker/ | grep -q 'http-equiv=\"Content-Security-Policy\"'"

# A.8.11 / A.5.34 data masking and privacy: published events never contain full addresses, hashes or passwords
check A.8.11 "200 latest public events: addresses truncated, no hash or password fields" bash -c "curl -sf '$API/api/events?limit=200' | $(printf %q "$PY") -c \"
import json, re, sys
ev = json.load(sys.stdin)
bad = [e for e in ev if not re.fullmatch(r'(\d+\.){3}x|[0-9a-f:]+::/48', e['src']) or {'src_hash', 'password', 'PASSWORD'} & e.keys()]
print(len(ev), 'events,', len(bad), 'violations'); sys.exit(1 if bad or not ev else 0)\""
check A.8.10 "tracker retention set to 30 days and no event older" bash -c "curl -sf '$API/api/stats?hours=720' | $(printf %q "$PY") -c \"
import json, sys, datetime as d
s = json.load(sys.stdin); age = (d.datetime.now(d.timezone.utc) - d.datetime.fromisoformat(s['first_event'].replace('Z', '+00:00'))).days
print('retention', s['retention_days'], 'days, oldest event', age, 'days'); sys.exit(0 if s['retention_days'] == 30 and age <= 31 else 1)\""

# A.8.15 / A.8.16 logging and monitoring: events still flowing; the uptime check runs on its schedule
check A.8.15 "honeypot logged an attack in the last hour" bash -c "curl -sf '$API/api/stats?hours=1' | $(printf %q "$PY") -c \"
import json, sys; s = json.load(sys.stdin); print(s['events'], 'events in the last hour'); sys.exit(0 if s['events'] else 1)\""
check A.8.16 "uptime check ran on its schedule in the last 2 hours and passed" bash -c "curl -sf '$REPO/actions/workflows/uptime.yml/runs?event=schedule&per_page=1' | $(printf %q "$PY") -c \"
import json, sys, datetime as d
runs = json.load(sys.stdin)['workflow_runs']
if not runs: print('no scheduled run ever'); sys.exit(1)
r = runs[0]; age = (d.datetime.now(d.timezone.utc) - d.datetime.fromisoformat(r['created_at'].replace('Z', '+00:00'))).total_seconds() / 60
print(f'last scheduled run {age:.0f} min ago, {r[\\\"conclusion\\\"]}'); sys.exit(0 if age <= 120 and r['conclusion'] == 'success' else 1)\""

# A.8.32 change management: main is protected and recent changes arrived through pull requests with passing CI
check A.8.32 "main requires a pull request and the CI test check" bash -c "curl -sf $REPO/rules/branches/main | $(printf %q "$PY") -c \"
import json, sys; t = {r['type'] for r in json.load(sys.stdin)}; print(sorted(t)); sys.exit(0 if {'pull_request', 'required_status_checks', 'non_fast_forward', 'deletion'} <= t else 1)\""
check A.8.32 "last 3 changes on main are merged pull requests whose test check passed" "$PY" -c "
import json, sys, urllib.request
get = lambda path: json.load(urllib.request.urlopen('$REPO/' + path))
sha, bad = 'main', 0
for _ in range(3):  # walk main's own history (first parents), not the commits inside each pull request
    c = get('commits/' + sha)
    ok = len(c['parents']) == 2 and any(r['name'] == 'test' and r['conclusion'] == 'success'
                                        for r in get('commits/' + c['sha'] + '/check-runs')['check_runs'])
    print(c['sha'][:7], 'merged PR, test passed' if ok else 'NOT a merged PR with passing test', end='; ')
    bad += not ok; sha = c['parents'][0]['sha']
sys.exit(1 if bad else 0)"

# A.6.8 event reporting
check A.6.8 "security policy published" bash -c "curl -sf https://raw.githubusercontent.com/shakthihs07-shs/ai-ids-iso27001/main/SECURITY.md | grep -q 'Report a vulnerability'"

echo "# $fails failed"
exit $((fails > 0))
