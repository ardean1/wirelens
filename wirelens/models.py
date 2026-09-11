"""Pydantic / dataclass models for WireLens."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class SuspicionFlag:
    id: str
    description: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ConnectionRecord:
    key: str
    proto: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    process_exe: Optional[str] = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    remote_hostname: Optional[str] = None
    addr_class: str = "unknown"  # private | cgnat | public | loopback | link_local
    flags: list[SuspicionFlag] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class DnsCacheEntry:
    ip: str
    hostname: Optional[str]
    resolved_at: float
    ttl_seconds: float
    source: str = "reverse"  # reverse | synthetic

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


RULE_CATALOG: list[dict[str, str]] = [
    {
        "id": "raw_ip",
        "description": "Remote address has no reverse DNS name in cache.",
    },
    {
        "id": "many_short",
        "description": "Same process contacted many short-lived remote endpoints in a recent window.",
    },
    {
        "id": "unusual_port",
        "description": "Remote port is outside the common-service allowlist.",
    },
    {
        "id": "cgnat_or_public",
        "description": "Address class tagging: private, CGNAT (100.64/10), or public.",
    },
    {
        "id": "blocklist_hit",
        "description": "Remote IP, hostname, or containing CIDR matches an optional blocklist entry.",
    },
]
