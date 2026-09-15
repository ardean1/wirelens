"""Rule-based suspicion flags for WireLens. Transparent, no threat-intel scores."""

from __future__ import annotations

import ipaddress
import time
from pathlib import Path
from typing import Iterable, Optional

from .models import ConnectionRecord, SuspicionFlag

# Common remote ports that are generally expected on a workstation/server.
COMMON_REMOTE_PORTS: frozenset[int] = frozenset(
    {
        20,
        21,
        22,
        25,
        53,
        80,
        110,
        123,
        143,
        443,
        465,
        587,
        853,
        993,
        995,
        1194,
        3306,
        3389,
        5432,
        5900,
        8080,
        8443,
    }
)

# Defaults for many_short
MANY_SHORT_WINDOW_SEC = 60.0
MANY_SHORT_MIN_REMOTES = 8
MANY_SHORT_MAX_LIFETIME_SEC = 5.0


def classify_address(addr: str) -> str:
    """Classify an IP as loopback, link_local, private, cgnat, or public."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "unknown"

    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    # CGNAT / shared address space: 100.64.0.0/10 (RFC 6598)
    if isinstance(ip, ipaddress.IPv4Address):
        if ipaddress.IPv4Address("100.64.0.0") <= ip <= ipaddress.IPv4Address("100.127.255.255"):
            return "cgnat"
    if ip.is_private:
        return "private"
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "other"
    return "public"


def is_unusual_port(port: int, allowlist: Optional[frozenset[int]] = None) -> bool:
    allow = allowlist if allowlist is not None else COMMON_REMOTE_PORTS
    if port <= 0:
        return False
    return port not in allow


def load_blocklist(path: Path | str) -> tuple[set[str], list[ipaddress._BaseNetwork]]:
    """Load domains/IPs/CIDRs from a blocklist file. Returns (hosts, networks)."""
    hosts: set[str] = set()
    networks: list[ipaddress._BaseNetwork] = []
    p = Path(path)
    if not p.is_file():
        return hosts, networks
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue
        lower = line.lower()
        try:
            if "/" in line:
                networks.append(ipaddress.ip_network(line, strict=False))
            else:
                try:
                    hosts.add(str(ipaddress.ip_address(line)))
                except ValueError:
                    hosts.add(lower)
        except ValueError:
            hosts.add(lower)
    return hosts, networks


def blocklist_match(
    remote_addr: str,
    hostname: Optional[str],
    hosts: set[str],
    networks: list[ipaddress._BaseNetwork],
) -> Optional[str]:
    """Return a short match detail if remote IP or hostname hits the blocklist."""
    if not hosts and not networks:
        return None
    try:
        ip = ipaddress.ip_address(remote_addr)
        if str(ip) in hosts:
            return f"IP {remote_addr}"
        for net in networks:
            if ip in net:
                return f"IP {remote_addr} in {net}"
    except ValueError:
        pass
    if hostname:
        h = hostname.lower().rstrip(".")
        if h in hosts:
            return f"hostname {hostname}"
        # suffix match: blocklist entry "evil.invalid" matches "a.evil.invalid"
        for entry in hosts:
            if "/" in entry or _looks_like_ip(entry):
                continue
            if h == entry or h.endswith("." + entry):
                return f"hostname {hostname} matches {entry}"
    return None


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def evaluate_raw_ip(hostname: Optional[str], remote_addr: str) -> Optional[SuspicionFlag]:
    """Flag when there is no reverse name for a non-private remote."""
    addr_class = classify_address(remote_addr)
    if addr_class in ("loopback", "link_local", "private", "other", "unknown"):
        return None
    if hostname:
        return None
    return SuspicionFlag(
        id="raw_ip",
        description="No hostname found for this remote address — destination name is unknown (not proof of malware).",
        detail=f"{remote_addr} ({addr_class}) unresolved",
    )


def evaluate_unusual_port(remote_port: int) -> Optional[SuspicionFlag]:
    if is_unusual_port(remote_port):
        return SuspicionFlag(
            id="unusual_port",
            description="Remote port is uncommon on a typical PC — worth a quick look, often still legitimate.",
            detail=f"port {remote_port}",
        )
    return None


def evaluate_cgnat_or_public(remote_addr: str) -> SuspicionFlag:
    """Always emit a tagging flag for address class (informational)."""
    cls = classify_address(remote_addr)
    return SuspicionFlag(
        id="cgnat_or_public",
        description="Address type tag (home/private, carrier CGNAT, or public internet) — informational only.",
        detail=cls,
    )


def evaluate_blocklist(
    remote_addr: str,
    hostname: Optional[str],
    hosts: set[str],
    networks: list[ipaddress._BaseNetwork],
) -> Optional[SuspicionFlag]:
    detail = blocklist_match(remote_addr, hostname, hosts, networks)
    if not detail:
        return None
    return SuspicionFlag(
        id="blocklist_hit",
        description="Matched your optional blocklist file — you (or the example list) marked this destination.",
        detail=detail,
    )


def evaluate_many_short(
    records: Iterable[ConnectionRecord],
    now: Optional[float] = None,
    window_sec: float = MANY_SHORT_WINDOW_SEC,
    min_remotes: int = MANY_SHORT_MIN_REMOTES,
    max_lifetime_sec: float = MANY_SHORT_MAX_LIFETIME_SEC,
) -> dict[int, SuspicionFlag]:
    """
    Return {pid: flag} for processes with many short-lived distinct remotes in window.
    A connection is short-lived if (last_seen - first_seen) <= max_lifetime_sec
    and last_seen is within window_sec of now.
    """
    now = now if now is not None else time.time()
    # pid -> set of remote keys
    by_pid: dict[int, set[str]] = {}
    for rec in records:
        if rec.pid is None:
            continue
        lifetime = max(0.0, rec.last_seen - rec.first_seen)
        if lifetime > max_lifetime_sec:
            continue
        if now - rec.last_seen > window_sec:
            continue
        remote_key = f"{rec.remote_addr}:{rec.remote_port}"
        by_pid.setdefault(rec.pid, set()).add(remote_key)

    out: dict[int, SuspicionFlag] = {}
    for pid, remotes in by_pid.items():
        if len(remotes) >= min_remotes:
            out[pid] = SuspicionFlag(
                id="many_short",
                description="Same program opened many short connections quickly — can be normal (browsers, updaters) or worth checking.",
                detail=f"pid {pid}: {len(remotes)} remotes in {window_sec:.0f}s",
            )
    return out


def apply_flags(
    record: ConnectionRecord,
    *,
    blocklist_hosts: Optional[set[str]] = None,
    blocklist_networks: Optional[list] = None,
    many_short_flag: Optional[SuspicionFlag] = None,
    include_addr_class: bool = True,
) -> list[SuspicionFlag]:
    """Compute all applicable flags for a single connection record."""
    flags: list[SuspicionFlag] = []
    hosts = blocklist_hosts or set()
    networks = blocklist_networks or []

    if include_addr_class:
        flags.append(evaluate_cgnat_or_public(record.remote_addr))

    f = evaluate_raw_ip(record.remote_hostname, record.remote_addr)
    if f:
        flags.append(f)

    f = evaluate_unusual_port(record.remote_port)
    if f:
        flags.append(f)

    f = evaluate_blocklist(record.remote_addr, record.remote_hostname, hosts, networks)
    if f:
        flags.append(f)

    if many_short_flag is not None:
        flags.append(many_short_flag)

    return flags
