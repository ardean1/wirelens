"""CLI entry: python -m wirelens [--demo] [--host] [--port] [--blocklist]."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="WireLens — local host network visibility dashboard")
    parser.add_argument("--demo", action="store_true", help="Synthesize plausible traffic (no privileges needed)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Bind port (default 8787)")
    parser.add_argument(
        "--blocklist",
        type=Path,
        default=None,
        help="Path to blocklist file (domains/IPs/CIDRs). Default: blocklists/example.txt if present.",
    )
    args = parser.parse_args()

    import uvicorn

    from .app import create_app

    app = create_app(demo=args.demo, blocklist_path=args.blocklist)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
