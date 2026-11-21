"""Honeypot collector: turns OpenCanary events into privacy-safe, ATT&CK-mapped records and serves them.

  GET /api/health      liveness and the time of the last event
  GET /api/events      latest events, newest first (?limit=, ?before_id=)
  GET /api/stats       counts for the last ?hours= (default 24): services, techniques, countries, hours,
                       usernames tried, web paths probed, distinct sources
  GET /api/stream      server-sent events: every new event as it is stored

Everything an attacker sends is hostile input: it is length-capped and stripped of control characters
here, and escaped by the page. Privacy (IP addresses are personal data under GDPR): the full address
is used once, in memory, for the country lookup and a daily keyed hash that counts distinct sources;
only the country, the address with its last part removed and that hash are stored. Passwords are never
stored. Events are deleted after RETENTION_DAYS.
"""
import asyncio
import bisect
import csv
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOG = Path(os.environ.get("OPENCANARY_LOG", "/var/log/opencanary/opencanary.log"))
DB = Path(os.environ.get("TRACKER_DB", "/data/tracker.db"))
GEO = Path(os.environ.get("GEO_DB", "/app/dbip-country-lite.csv.gz"))
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))
MAX_STREAMS = 100

BRUTE, SCAN, VULN, EXPLOIT = "T1110 Brute Force", "T1595 Active Scanning", "T1595.002 Vulnerability Scanning", "T1190 Exploit Public-Facing Application"
# OpenCanary logtype -> (service, what happened, ATT&CK technique); 1000-1006 are OpenCanary's own messages
EVENTS = {
    2000: ("FTP", "login attempt", BRUTE), 2001: ("FTP", "connection", SCAN),
    3000: ("HTTP", "request", None), 3001: ("HTTP", "login attempt", BRUTE),
    3002: ("HTTP", "request", SCAN), 3003: ("HTTP", "request", SCAN),
    4000: ("SSH", "connection", SCAN), 4001: ("SSH", "handshake", SCAN), 4002: ("SSH", "login attempt", BRUTE),
    5001: ("Port scan", "scan", "T1046 Network Service Discovery"), 5002: ("Port scan", "OS fingerprint", "T1046 Network Service Discovery"),
    5003: ("Port scan", "scan", "T1046 Network Service Discovery"), 5004: ("Port scan", "scan", "T1046 Network Service Discovery"),
    5005: ("Port scan", "scan", "T1046 Network Service Discovery"),
    6001: ("Telnet", "login attempt", BRUTE), 6002: ("Telnet", "connection", SCAN),
    7001: ("HTTP proxy", "login attempt", BRUTE),
    8001: ("MySQL", "login attempt", BRUTE), 9003: ("MySQL", "connection", SCAN),
    9001: ("MSSQL", "login attempt", BRUTE), 9002: ("MSSQL", "login attempt", BRUTE),
    10001: ("TFTP", "file request", "T1105 Ingress Tool Transfer"),
    11001: ("NTP", "monlist query", "T1498.002 Reflection Amplification"),
    12001: ("VNC", "login attempt", BRUTE),
    13001: ("SNMP", "query", "T1602.001 SNMP (MIB Dump)"),
    14001: ("RDP", "login attempt", BRUTE),
    15001: ("SIP", "request", SCAN),
    16001: ("Git", "clone request", "T1213.003 Code Repositories"),
    17001: ("Redis", "command", EXPLOIT),
    18001: ("TCP", "connection", SCAN), 18002: ("TCP", "connection", SCAN), 18003: ("TCP", "data", SCAN),
    18004: ("TCP", "data", SCAN), 18005: ("TCP", "data", SCAN),
    20001: ("MongoDB", "login attempt", BRUTE),
}
# Web paths that try to exploit something (traversal, injection, known router/framework bugs), not just look
EXPLOIT_PATH = re.compile(r"\.\./|%2e%2e|/etc/passwd|\$\{jndi|cmd=|exec=|;\s*(wget|curl|sh)\b|\b(wget|curl)\s+http|<script|"
                          r"union\s+(all\s+)?select|eval-stdin|/boaform|/hnap1|/cgi-bin/.*\.(sh|cgi)|shell\?|/goform/|"
                          r"/setup\.cgi|/vendor/phpunit|/actuator/gateway|think\\app|invokefunction", re.I)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean(value, limit):
    """Hostile text from the network: printable only, capped."""
    s = CONTROL.sub("", str(value))
    return s[:limit] + ("…" if len(s) > limit else "")


def mask_ip(ip: ipaddress._BaseAddress) -> str:
    """The address with its host part removed: 203.0.113.x, or the /48 prefix for IPv6."""
    if ip.version == 4:
        return ".".join(str(ip).split(".")[:3]) + ".x"
    return str(ipaddress.ip_network(f"{ip}/48", strict=False).network_address).rstrip(":") + "::/48"


def web_technique(path: str) -> str:
    if EXPLOIT_PATH.search(path):
        return EXPLOIT
    return SCAN if path in ("", "/", "/index.html") else VULN  # OpenCanary redirects / to /index.html


class Geo:
    """Country lookup from DB-IP's free IP-to-Country Lite database (CC BY 4.0): sorted ranges + bisect."""

    def __init__(self, path: Path):
        self.ranges = {4: ([], [], []), 6: ([], [], [])}
        if not path.exists():
            return
        with gzip.open(path, "rt", newline="") as f:
            for start, end, country in csv.reader(f):
                a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
                starts, ends, countries = self.ranges[a.version]
                starts.append(int(a)); ends.append(int(b)); countries.append(country)

    def country(self, ip: ipaddress._BaseAddress) -> str:
        starts, ends, countries = self.ranges[ip.version]
        i = bisect.bisect_right(starts, int(ip)) - 1
        return countries[i] if i >= 0 and int(ip) <= ends[i] else "ZZ"


class DailyHasher:
    """Keyed hash of the source address, with a random key per UTC day that is never written to disk:
    distinct sources can be counted within a day, but a stored hash cannot be turned back into an address."""

    def __init__(self):
        self.day, self.key = None, b""

    def __call__(self, ip: str, day: str) -> str:
        if day != self.day:
            self.day, self.key = day, secrets.token_bytes(32)
        return hmac.new(self.key, ip.encode(), hashlib.sha256).hexdigest()[:16]


def parse_event(line: str, geo: Geo, hasher: DailyHasher) -> dict | None:
    """One OpenCanary JSON log line -> a record that is safe to store and publish, or None to skip."""
    try:
        e = json.loads(line)
        kind = EVENTS.get(int(e.get("logtype", 0)))
        ip = ipaddress.ip_address(str(e.get("src_host", "")).strip())
    except (ValueError, TypeError, AttributeError):
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if kind is None or not ip.is_global:
        return None
    service, action, technique = kind
    data = e.get("logdata") if isinstance(e.get("logdata"), dict) else {}
    try:
        ts = datetime.strptime(str(e.get("utc_time")), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except ValueError:
        ts = datetime.now(timezone.utc)
    detail = {}
    if "USERNAME" in data:
        detail["username"] = clean(data["USERNAME"], 64)
    if "PATH" in data:
        detail["path"] = clean(data["PATH"], 160)
    if "USERAGENT" in data:
        detail["useragent"] = clean(data["USERAGENT"], 160)
    if "CMD" in data:
        detail["command"] = clean(data["CMD"], 80)
    if "FILENAME" in data:
        detail["filename"] = clean(data["FILENAME"], 120)
    if service == "HTTP" and technique is None:
        technique = web_technique(detail.get("path", ""))
    try:
        port = int(e.get("dst_port", -1))
    except (TypeError, ValueError):
        port = -1
    return {"ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "service": service, "port": port, "action": action,
            "technique": technique, "country": geo.country(ip), "src": mask_ip(ip),
            "src_hash": hasher(str(ip), ts.strftime("%Y-%m-%d")), "detail": json.dumps(detail, ensure_ascii=False)}


# ---------------------------------------------------------------- storage
SCHEMA = """CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, service TEXT, port INTEGER,
            action TEXT, technique TEXT, country TEXT, src TEXT, src_hash TEXT, detail TEXT);
            CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
            CREATE TABLE IF NOT EXISTS cursor (id INTEGER PRIMARY KEY CHECK (id = 1), inode INTEGER, pos INTEGER);"""
COLUMNS = ("ts", "service", "port", "action", "technique", "country", "src", "src_hash", "detail")


def connect(path: Path = DB) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    return con


def store(con: sqlite3.Connection, rec: dict):
    con.execute(f"INSERT INTO events ({','.join(COLUMNS)}) VALUES ({','.join('?' * len(COLUMNS))})", [rec[c] for c in COLUMNS])


def save(con: sqlite3.Connection, rec: dict | None, cursor: dict):
    """Store an event (if any) and the log position after it in one transaction: a restart neither repeats nor skips."""
    con.execute("BEGIN")
    if rec:
        store(con, rec)
    con.execute("INSERT OR REPLACE INTO cursor VALUES (1, ?, ?)", (cursor["inode"], cursor["pos"]))
    con.execute("COMMIT")


def purge(con: sqlite3.Connection, days: int = RETENTION_DAYS):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    con.execute("DELETE FROM events WHERE ts < ?", (cutoff,))


def public(row: sqlite3.Row) -> dict:
    """What the API shows: everything stored except the source hash."""
    return {"id": row["id"], "ts": row["ts"], "service": row["service"], "port": row["port"], "action": row["action"],
            "technique": row["technique"], "country": row["country"], "src": row["src"], **json.loads(row["detail"] or "{}")}


def stats(con: sqlite3.Connection, hours: int) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    q = lambda sql, *a: con.execute(sql, (since, *a)).fetchall()
    top = lambda col, n: [{"key": r[0], "count": r[1]} for r in
                          q(f"SELECT {col}, COUNT(*) c FROM events WHERE ts >= ? GROUP BY 1 ORDER BY c DESC LIMIT ?", n)]
    detail = lambda key, n: [{"key": r[0], "count": r[1]} for r in
                             q(f"SELECT json_extract(detail, '$.{key}') k, COUNT(*) c FROM events WHERE ts >= ? AND k IS NOT NULL "
                               "AND k != '' GROUP BY 1 ORDER BY c DESC LIMIT ?", n)]
    total, sources, countries = q("SELECT COUNT(*), COUNT(DISTINCT src_hash), COUNT(DISTINCT country) FROM events WHERE ts >= ?")[0]
    first = con.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
    return {"hours": hours, "events": total, "distinct_sources": sources, "countries": countries,
            "login_attempts": q("SELECT COUNT(*) FROM events WHERE ts >= ? AND action = 'login attempt'")[0][0],
            "by_service": top("service", 20), "by_technique": top("technique", 20), "by_country": top("country", 15),
            "by_hour": [{"key": r[0], "count": r[1]} for r in
                        q("SELECT substr(ts, 1, 13) h, COUNT(*) FROM events WHERE ts >= ? GROUP BY 1 ORDER BY 1")],
            "usernames": detail("username", 12), "paths": detail("path", 12),
            "first_event": first[0], "last_event": first[1], "retention_days": RETENTION_DAYS}


# ---------------------------------------------------------------- log follower
def follow(path: Path, stop: threading.Event, cursor: dict | None = None):
    """Yield new lines as OpenCanary appends them; reopen when the log is rotated or truncated.
    cursor ({inode, pos}) is kept at the end of the last yielded line, and reading resumes there if it names this file."""
    cursor = {} if cursor is None else cursor
    f, inode = None, None
    while not stop.is_set():
        try:
            st = path.stat()
            if f is None or st.st_ino != inode or st.st_size < f.tell():
                if f:
                    f.close()
                f, inode = path.open("rb"), st.st_ino
                if cursor.get("inode") == inode and cursor.get("pos", 0) <= st.st_size:
                    f.seek(cursor["pos"])
            pos = f.tell()
            line = f.readline()
            if line.endswith(b"\n"):
                cursor.update(inode=inode, pos=f.tell())
                yield line.decode("utf-8", errors="replace")
                continue
            f.seek(pos)  # nothing new, or a half-written line: read it again once it is complete
        except FileNotFoundError:
            pass
        stop.wait(0.5)


def ingest_forever(con: sqlite3.Connection, stop: threading.Event):
    geo, hasher, last_purge = Geo(GEO), DailyHasher(), 0.0
    row = con.execute("SELECT inode, pos FROM cursor").fetchone()
    cursor = {"inode": row[0], "pos": row[1]} if row else {}
    for line in follow(LOG, stop, cursor):
        save(con, parse_event(line, geo, hasher), cursor)
        if time.time() - last_purge > 3600:
            purge(con); last_purge = time.time()


# ---------------------------------------------------------------- API
def create_app(con: sqlite3.Connection | None = None, ingest: bool = True):
    from contextlib import asynccontextmanager

    from fastapi import FastAPI, HTTPException, Query
    from fastapi.responses import StreamingResponse

    con = con or connect()
    state = {"streams": 0, "stop": threading.Event()}

    @asynccontextmanager
    async def lifespan(app):
        if ingest:
            threading.Thread(target=ingest_forever, args=(connect(), state["stop"]), daemon=True).start()
        yield
        state["stop"].set()

    app = FastAPI(title="Honeypot attack tracker", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "last_event": con.execute("SELECT MAX(ts) FROM events").fetchone()[0]}

    @app.get("/api/events")
    def events(limit: int = Query(50, ge=1, le=200), before_id: int | None = Query(None, ge=1)):
        sql, args = "SELECT * FROM events", []
        if before_id:
            sql, args = sql + " WHERE id < ?", [before_id]
        return [public(r) for r in con.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, limit))]

    @app.get("/api/stats")
    def get_stats(hours: int = Query(24, ge=1, le=24 * RETENTION_DAYS)):
        return stats(con, hours)

    @app.get("/api/stream")
    async def stream():
        if state["streams"] >= MAX_STREAMS:
            raise HTTPException(503, "too many viewers, try again shortly")

        async def gen():
            state["streams"] += 1
            try:
                last = con.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
                idle = 0
                while True:
                    rows = con.execute("SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 200", (last,)).fetchall()
                    for r in rows:
                        last = r["id"]
                        yield f"data: {json.dumps(public(r), ensure_ascii=False)}\n\n"
                    idle = 0 if rows else idle + 1
                    if idle >= 15:  # keep proxies from closing a quiet stream
                        yield ": keep-alive\n\n"; idle = 0
                    await asyncio.sleep(1)
            finally:
                state["streams"] -= 1

        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    return app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(create_app(), host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), proxy_headers=False)
