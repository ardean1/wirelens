"""Unit tests for WireLens suspicion helpers."""

from __future__ import annotations

import time
from pathlib import Path

from wirelens.models import ConnectionRecord
from wirelens.suspicion import (
    COMMON_REMOTE_PORTS,
    apply_flags,
    blocklist_match,
    classify_address,
    evaluate_many_short,
    evaluate_raw_ip,
    evaluate_unusual_port,
    is_unusual_port,
    load_blocklist,
)


def test_classify_private_loopback_public_cgnat():
    assert classify_address("10.0.0.1") == "private"
    assert classify_address("192.168.1.10") == "private"
    assert classify_address("127.0.0.1") == "loopback"
    assert classify_address("8.8.8.8") == "public"
    assert classify_address("100.64.0.1") == "cgnat"
    assert classify_address("100.127.255.255") == "cgnat"
    assert classify_address("100.63.255.255") != "cgnat"  # just below CGNAT
    assert classify_address("169.254.1.1") == "link_local"


def test_unusual_port_allowlist():
    for p in (80, 443, 53, 123, 22, 25, 587, 993, 995, 3389, 853):
        assert p in COMMON_REMOTE_PORTS
        assert not is_unusual_port(p)
    assert is_unusual_port(31337)
    assert is_unusual_port(4444)
    flag = evaluate_unusual_port(31337)
    assert flag is not None and flag.id == "unusual_port"
    assert evaluate_unusual_port(443) is None


def test_raw_ip_only_for_public_unresolved():
    assert evaluate_raw_ip(None, "10.0.0.5") is None
    assert evaluate_raw_ip(None, "127.0.0.1") is None
    assert evaluate_raw_ip("dns.google", "8.8.8.8") is None
    flag = evaluate_raw_ip(None, "8.8.8.8")
    assert flag is not None and flag.id == "raw_ip"
    # CGNAT without name also flagged as raw_ip
    flag2 = evaluate_raw_ip(None, "100.64.1.2")
    assert flag2 is not None and flag2.id == "raw_ip"


def test_blocklist_ip_cidr_domain(tmp_path: Path):
    bl = tmp_path / "bl.txt"
    bl.write_text(
        "# comment\n"
        "203.0.113.66\n"
        "198.51.100.0/24\n"
        "malware.example\n"
        "evil.invalid  # inline\n",
        encoding="utf-8",
    )
    hosts, nets = load_blocklist(bl)
    assert "203.0.113.66" in hosts
    assert "malware.example" in hosts
    assert "evil.invalid" in hosts
    assert len(nets) == 1

    assert blocklist_match("203.0.113.66", None, hosts, nets)
    assert blocklist_match("198.51.100.50", None, hosts, nets)
    assert blocklist_match("1.2.3.4", "a.malware.example", hosts, nets)
    assert blocklist_match("1.2.3.4", "evil.invalid", hosts, nets)
    assert blocklist_match("1.2.3.4", "ok.example", hosts, nets) is None


def test_many_short_window():
    now = time.time()
    records = []
    for i in range(10):
        records.append(
            ConnectionRecord(
                key=f"k{i}",
                proto="tcp",
                local_addr="192.168.1.2",
                local_port=50000 + i,
                remote_addr=f"198.51.100.{i}",
                remote_port=40000 + i,
                state="TIME_WAIT",
                pid=42,
                process_name="curl",
                first_seen=now - 1.0,
                last_seen=now,
            )
        )
    # One long-lived should not count toward short set for another pid
    records.append(
        ConnectionRecord(
            key="long",
            proto="tcp",
            local_addr="192.168.1.2",
            local_port=49999,
            remote_addr="8.8.8.8",
            remote_port=443,
            state="ESTABLISHED",
            pid=99,
            process_name="chrome",
            first_seen=now - 120,
            last_seen=now,
        )
    )
    flags = evaluate_many_short(records, now=now, min_remotes=8)
    assert 42 in flags
    assert flags[42].id == "many_short"
    assert 99 not in flags


def test_apply_flags_combines(tmp_path: Path):
    bl = tmp_path / "bl.txt"
    # Use a globally routable IP (not TEST-NET / RFC private documentation ranges)
    bl.write_text("1.2.3.4\n", encoding="utf-8")
    hosts, nets = load_blocklist(bl)
    rec = ConnectionRecord(
        key="x",
        proto="tcp",
        local_addr="192.168.1.2",
        local_port=1,
        remote_addr="1.2.3.4",
        remote_port=31337,
        state="ESTABLISHED",
        pid=1,
        remote_hostname=None,
    )
    flags = apply_flags(rec, blocklist_hosts=hosts, blocklist_networks=nets)
    ids = {f.id for f in flags}
    assert "cgnat_or_public" in ids
    assert "unusual_port" in ids
    assert "blocklist_hit" in ids
    assert "raw_ip" in ids
    assert any(f.detail == "public" for f in flags if f.id == "cgnat_or_public")
