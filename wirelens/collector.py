"""Connection + DNS reverse-cache collector for WireLens."""

from __future__ import annotations

import random
import socket
import threading
import time
from pathlib import Path
from typing import Any, Optional

import psutil

from .models import ConnectionRecord, DnsCacheEntry
from .suspicion import apply_flags, evaluate_many_short, load_blocklist

DNS_TTL_SEC = 300.0
POLL_INTERVAL_SEC = 2.0


class Collector:
    """Polls host connections (or synthesizes demo traffic) and maintains DNS cache."""

    def __init__(
        self,
        *,
        demo: bool = False,
        blocklist_path: Optional[Path] = None,
        poll_interval: float = POLL_INTERVAL_SEC,
        dns_ttl: float = DNS_TTL_SEC,
    ) -> None:
        self.demo = demo
        self.poll_interval = poll_interval
        self.dns_ttl = dns_ttl
        self._lock = threading.RLock()
        self._connections: dict[str, ConnectionRecord] = {}
        self._dns: dict[str, DnsCacheEntry] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._blocklist_path = blocklist_path
        self._bl_hosts: set[str] = set()
        self._bl_nets: list = []
        self._demo_tick = 0
        self._started_at = time.time()
        if blocklist_path:
            self.reload_blocklist()

    def reload_blocklist(self) -> None:
        if self._blocklist_path:
            self._bl_hosts, self._bl_nets = load_blocklist(self._blocklist_path)

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._loop, name="wirelens-collector", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def _loop(self) -> None:
        while True:
            with self._lock:
                if not self._running:
                    break
            try:
                self.poll_once()
            except Exception:
                # Keep collector alive; UI still works with last snapshot.
                pass
            time.sleep(self.poll_interval)

    def poll_once(self) -> None:
        now = time.time()
        if self.demo:
            snap = self._demo_snapshot(now)
        else:
            snap = self._live_snapshot(now)

        # Figure out which remotes need DNS *without* holding the lock for lookups.
        need_dns: list[str] = []
        with self._lock:
            seen_keys: set[str] = set()
            for rec in snap:
                seen_keys.add(rec.key)
                existing = self._connections.get(rec.key)
                if existing:
                    existing.last_seen = now
                    existing.state = rec.state
                    existing.pid = rec.pid or existing.pid
                    existing.process_name = rec.process_name or existing.process_name
                    existing.process_exe = rec.process_exe or existing.process_exe
                else:
                    rec.first_seen = now
                    rec.last_seen = now
                    self._connections[rec.key] = rec
                entry = self._dns.get(rec.remote_addr)
                if not entry or (now - entry.resolved_at) >= self.dns_ttl:
                    if rec.remote_addr not in need_dns:
                        need_dns.append(rec.remote_addr)

            stale_after = self.poll_interval * 4
            to_del = [
                k
                for k, r in self._connections.items()
                if k not in seen_keys and (now - r.last_seen) > stale_after
            ]
            for k in to_del:
                del self._connections[k]

        # Reverse DNS outside the lock (short timeout) so /api/health and WS stay responsive.
        for ip in need_dns[:40]:  # cap per poll so one slow wave cannot stall forever
            self._resolve_dns(ip, now)

        with self._lock:
            self._enrich_and_flag(now)

    def _resolve_dns(self, ip: str, now: float) -> None:
        """Resolve one IP with a short timeout; never holds self._lock."""
        with self._lock:
            entry = self._dns.get(ip)
            if entry and (now - entry.resolved_at) < self.dns_ttl:
                return
        hostname: Optional[str] = None
        source = "reverse"
        if self.demo:
            hostname = self._demo_hostname(ip)
            source = "synthetic"
        else:
            old_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(0.4)
                hostname, _ = socket.getnameinfo((ip, 0), 0)
                if hostname == ip:
                    hostname = None
            except OSError:
                hostname = None
            finally:
                socket.setdefaulttimeout(old_timeout)
        with self._lock:
            self._dns[ip] = DnsCacheEntry(
                ip=ip,
                hostname=hostname,
                resolved_at=now,
                ttl_seconds=self.dns_ttl,
                source=source,
            )

    def _enrich_and_flag(self, now: float) -> None:
        records = list(self._connections.values())
        for rec in records:
            dns = self._dns.get(rec.remote_addr)
            rec.remote_hostname = dns.hostname if dns else None
            from .suspicion import classify_address

            rec.addr_class = classify_address(rec.remote_addr)

        many = evaluate_many_short(records, now=now)
        for rec in records:
            ms = many.get(rec.pid) if rec.pid is not None else None
            rec.flags = apply_flags(
                rec,
                blocklist_hosts=self._bl_hosts,
                blocklist_networks=self._bl_nets,
                many_short_flag=ms,
            )

    def _live_snapshot(self, now: float) -> list[ConnectionRecord]:
        out: list[ConnectionRecord] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []

        proc_cache: dict[int, tuple[Optional[str], Optional[str]]] = {}

        for c in conns:
            if not c.raddr:
                continue
            laddr = c.laddr
            raddr = c.raddr
            if not laddr or not raddr:
                continue
            local_ip, local_port = laddr.ip, laddr.port
            remote_ip, remote_port = raddr.ip, raddr.port
            # Normalize IPv6-mapped
            if local_ip.startswith("::ffff:"):
                local_ip = local_ip[7:]
            if remote_ip.startswith("::ffff:"):
                remote_ip = remote_ip[7:]

            # psutil type distinguishes TCP/UDP
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            state = (c.status or "NONE").upper()
            pid = c.pid
            pname: Optional[str] = None
            pexe: Optional[str] = None
            if pid:
                if pid not in proc_cache:
                    try:
                        p = psutil.Process(pid)
                        proc_cache[pid] = (p.name(), p.exe())
                    except (psutil.Error, OSError):
                        proc_cache[pid] = (None, None)
                pname, pexe = proc_cache[pid]

            key = f"{proto}|{local_ip}:{local_port}|{remote_ip}:{remote_port}|{pid or 0}"
            out.append(
                ConnectionRecord(
                    key=key,
                    proto=proto,
                    local_addr=local_ip,
                    local_port=local_port,
                    remote_addr=remote_ip,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                    process_name=pname,
                    process_exe=pexe,
                    first_seen=now,
                    last_seen=now,
                )
            )
        return out

    # --- Demo mode ---------------------------------------------------------

    _DEMO_PROCS = [
        (1204, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
        (880, "svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
        (4412, "Code.exe", "C:\\Users\\Public\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"),
        (2100, "python.exe", "C:\\Python312\\python.exe"),
        (3301, "firefox", "/usr/lib/firefox/firefox"),
        (501, "curl", "/usr/bin/curl"),
    ]

    _DEMO_HOSTS = {
        "8.8.8.8": "dns.google",
        "1.1.1.1": "one.one.one.one",
        "142.250.72.14": "lga25s81-in-f14.1e100.net",
        "104.16.132.229": "cloudflare-cdn",
        "52.84.100.12": "server-52-84-100-12.iad61.r.cloudfront.net",
        "13.107.42.16": None,  # raw_ip candidate
        "185.199.108.153": "cdn-185-199-108-153.github.com",
        "100.64.12.40": None,  # CGNAT
        "10.0.0.5": None,
        "203.0.113.66": "malware.example",  # blocklist IP
        "198.51.100.23": None,
        "93.184.216.34": "example.com",
    }

    def _demo_hostname(self, ip: str) -> Optional[str]:
        if ip in self._DEMO_HOSTS:
            return self._DEMO_HOSTS[ip]
        # Stable synthetic name for others
        return f"host-{ip.replace('.', '-')}.lan.example"

    def _demo_snapshot(self, now: float) -> list[ConnectionRecord]:
        self._demo_tick += 1
        rng = random.Random(self._demo_tick // 3)  # change every ~3 polls
        out: list[ConnectionRecord] = []

        # Stable long-lived connections
        stables = [
            ("tcp", "192.168.1.50", 52100, "8.8.8.8", 53, "NONE", self._DEMO_PROCS[1]),
            ("udp", "192.168.1.50", 52101, "1.1.1.1", 53, "NONE", self._DEMO_PROCS[1]),
            ("tcp", "192.168.1.50", 49812, "142.250.72.14", 443, "ESTABLISHED", self._DEMO_PROCS[0]),
            ("tcp", "192.168.1.50", 49813, "104.16.132.229", 443, "ESTABLISHED", self._DEMO_PROCS[0]),
            ("tcp", "192.168.1.50", 50100, "52.84.100.12", 443, "ESTABLISHED", self._DEMO_PROCS[2]),
            ("tcp", "192.168.1.50", 50200, "185.199.108.153", 443, "ESTABLISHED", self._DEMO_PROCS[2]),
            ("tcp", "192.168.1.50", 50300, "93.184.216.34", 80, "ESTABLISHED", self._DEMO_PROCS[4]),
            ("tcp", "192.168.1.50", 50400, "10.0.0.5", 445, "ESTABLISHED", self._DEMO_PROCS[1]),
            ("tcp", "192.168.1.50", 50500, "100.64.12.40", 443, "ESTABLISHED", self._DEMO_PROCS[3]),
            ("tcp", "192.168.1.50", 50600, "13.107.42.16", 443, "ESTABLISHED", self._DEMO_PROCS[0]),
            ("tcp", "192.168.1.50", 50700, "203.0.113.66", 8080, "ESTABLISHED", self._DEMO_PROCS[5]),
            ("tcp", "127.0.0.1", 8787, "127.0.0.1", 51234, "ESTABLISHED", self._DEMO_PROCS[3]),
        ]

        for proto, lip, lp, rip, rp, state, proc in stables:
            pid, name, exe = proc
            key = f"{proto}|{lip}:{lp}|{rip}:{rp}|{pid}"
            out.append(
                ConnectionRecord(
                    key=key,
                    proto=proto,
                    local_addr=lip,
                    local_port=lp,
                    remote_addr=rip,
                    remote_port=rp,
                    state=state,
                    pid=pid,
                    process_name=name,
                    process_exe=exe,
                    first_seen=now - 120,
                    last_seen=now,
                )
            )

        # Short-lived burst from one process (triggers many_short)
        burst_pid, burst_name, burst_exe = self._DEMO_PROCS[5]
        for i in range(10):
            rip = f"198.51.100.{10 + i}"
            rp = 40000 + (self._demo_tick % 50) + i
            lip = "192.168.1.50"
            lp = 51000 + i
            key = f"tcp|{lip}:{lp}|{rip}:{rp}|{burst_pid}"
            out.append(
                ConnectionRecord(
                    key=key,
                    proto="tcp",
                    local_addr=lip,
                    local_port=lp,
                    remote_addr=rip,
                    remote_port=rp,
                    state="TIME_WAIT" if i % 2 else "SYN_SENT",
                    pid=burst_pid,
                    process_name=burst_name,
                    process_exe=burst_exe,
                    first_seen=now - 1.5,
                    last_seen=now,
                )
            )

        # Occasional unusual port
        if self._demo_tick % 5 == 0:
            pid, name, exe = self._DEMO_PROCS[3]
            rip = "198.51.100.23"
            key = f"tcp|192.168.1.50:52001|{rip}:31337|{pid}"
            out.append(
                ConnectionRecord(
                    key=key,
                    proto="tcp",
                    local_addr="192.168.1.50",
                    local_port=52001,
                    remote_addr=rip,
                    remote_port=31337,
                    state="ESTABLISHED",
                    pid=pid,
                    process_name=name,
                    process_exe=exe,
                    first_seen=now - 10,
                    last_seen=now,
                )
            )

        # Seed DNS for demo IPs
        for ip in list(self._DEMO_HOSTS.keys()) + [f"198.51.100.{10 + i}" for i in range(10)]:
            if ip not in self._dns or (now - self._dns[ip].resolved_at) >= self.dns_ttl:
                self._dns[ip] = DnsCacheEntry(
                    ip=ip,
                    hostname=self._demo_hostname(ip) if ip in self._DEMO_HOSTS else None,
                    resolved_at=now,
                    ttl_seconds=self.dns_ttl,
                    source="synthetic",
                )

        _ = rng  # reserved for future jitter
        return out

    # --- Snapshot API ------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            conns = [c.to_dict() for c in sorted(self._connections.values(), key=lambda r: r.last_seen, reverse=True)]
            dns = [e.to_dict() for e in sorted(self._dns.values(), key=lambda e: e.resolved_at, reverse=True)]
            return {
                "ts": time.time(),
                "demo": self.demo,
                "uptime_sec": time.time() - self._started_at,
                "connection_count": len(conns),
                "dns_count": len(dns),
                "connections": conns,
                "dns": dns,
            }

    def connections(self) -> list[dict[str, Any]]:
        return self.snapshot()["connections"]

    def dns_entries(self) -> list[dict[str, Any]]:
        return self.snapshot()["dns"]
