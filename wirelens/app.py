"""FastAPI application: REST + WebSocket for WireLens."""

from __future__ import annotations

import asyncio
import csv
import io
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .collector import Collector
from .models import RULE_CATALOG

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEFAULT_BLOCKLIST = Path(__file__).resolve().parent.parent / "blocklists" / "example.txt"

collector: Optional[Collector] = None


def create_app(
    *,
    demo: bool = False,
    blocklist_path: Optional[Path] = None,
) -> FastAPI:
    global collector
    bl = blocklist_path if blocklist_path is not None else DEFAULT_BLOCKLIST
    collector = Collector(demo=demo, blocklist_path=bl if bl.is_file() else None)
    collector.start()

    app = FastAPI(title="WireLens", version="1.0.0", docs_url="/api/docs")

    @app.on_event("shutdown")
    def _shutdown() -> None:
        if collector:
            collector.stop()

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        assert collector is not None
        snap = collector.snapshot()
        return {
            "ok": True,
            "demo": snap["demo"],
            "uptime_sec": snap["uptime_sec"],
            "connection_count": snap["connection_count"],
            "dns_count": snap["dns_count"],
        }

    @app.get("/api/connections")
    def api_connections(
        q: Optional[str] = Query(None, description="Search filter"),
        suspicious_only: bool = Query(False),
    ) -> dict[str, Any]:
        assert collector is not None
        rows = collector.connections()
        if suspicious_only:
            rows = [r for r in rows if _is_suspicious(r)]
        if q:
            rows = [r for r in rows if _matches(r, q)]
        return {"count": len(rows), "connections": rows}

    @app.get("/api/dns")
    def api_dns() -> dict[str, Any]:
        assert collector is not None
        entries = collector.dns_entries()
        return {"count": len(entries), "dns": entries}

    @app.get("/api/rules")
    def api_rules() -> dict[str, Any]:
        return {"rules": RULE_CATALOG}

    @app.get("/api/export.csv")
    def export_csv(
        suspicious_only: bool = Query(False),
        q: Optional[str] = Query(None),
    ) -> StreamingResponse:
        assert collector is not None
        rows = collector.connections()
        if suspicious_only:
            rows = [r for r in rows if _is_suspicious(r)]
        if q:
            rows = [r for r in rows if _matches(r, q)]

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "proto",
                "local_addr",
                "local_port",
                "remote_addr",
                "remote_port",
                "state",
                "pid",
                "process_name",
                "process_exe",
                "remote_hostname",
                "addr_class",
                "flags",
                "first_seen",
                "last_seen",
            ]
        )
        for r in rows:
            flag_ids = ",".join(f["id"] for f in r.get("flags") or [])
            writer.writerow(
                [
                    r.get("proto"),
                    r.get("local_addr"),
                    r.get("local_port"),
                    r.get("remote_addr"),
                    r.get("remote_port"),
                    r.get("state"),
                    r.get("pid"),
                    r.get("process_name"),
                    r.get("process_exe"),
                    r.get("remote_hostname"),
                    r.get("addr_class"),
                    flag_ids,
                    r.get("first_seen"),
                    r.get("last_seen"),
                ]
            )
        buf.seek(0)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=wirelens_connections.csv"},
        )

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket) -> None:
        await ws.accept()
        try:
            while True:
                assert collector is not None
                await ws.send_json(collector.snapshot())
                await asyncio.sleep(2.0)
        except WebSocketDisconnect:
            return
        except Exception:
            try:
                await ws.close()
            except Exception:
                pass

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app


def _is_suspicious(row: dict[str, Any]) -> bool:
    """True if any flag beyond pure informational private/loopback tagging."""
    flags = row.get("flags") or []
    for f in flags:
        fid = f.get("id")
        if fid in ("raw_ip", "many_short", "unusual_port", "blocklist_hit"):
            return True
        if fid == "cgnat_or_public" and f.get("detail") in ("cgnat", "public"):
            # Treat public/cgnat tagging alone as noteworthy for the toggle when
            # combined — but for "suspicious only" require stronger signals OR
            # cgnat (often interesting on hosts). Keep public alone out.
            if f.get("detail") == "cgnat":
                return True
    return False


def _matches(row: dict[str, Any], q: str) -> bool:
    needle = q.lower()
    hay = " ".join(
        str(x)
        for x in [
            row.get("proto"),
            row.get("local_addr"),
            row.get("local_port"),
            row.get("remote_addr"),
            row.get("remote_port"),
            row.get("state"),
            row.get("pid"),
            row.get("process_name"),
            row.get("process_exe"),
            row.get("remote_hostname"),
            row.get("addr_class"),
            " ".join(f.get("id", "") for f in (row.get("flags") or [])),
            " ".join(f.get("detail", "") for f in (row.get("flags") or [])),
        ]
        if x is not None
    ).lower()
    return needle in hay
