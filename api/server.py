"""
api/server.py
FastAPI backend — serves threat + packet data as REST API.
Also serves the web dashboard HTML.
Runs alongside the capture loop via asyncio.
"""

import asyncio
import ipaddress
import json
import os
import sys
from datetime import datetime
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import API_HOST, API_PORT

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

app = FastAPI(title="AI Wireshark API", version="3.0") if FASTAPI_AVAILABLE else None

if FASTAPI_AVAILABLE and app:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[f"http://localhost:{API_PORT}", f"http://127.0.0.1:{API_PORT}"],
        allow_methods=["GET", "DELETE"],
        allow_headers=["*"],
    )

# Shared state — populated by main.py
_threats:  deque = deque(maxlen=200)
_packets:  deque = deque(maxlen=500)
_stats:    dict  = {}
_blocked:  list  = []
_sse_queue: asyncio.Queue = asyncio.Queue()


def push_threat(threat: dict):
    """Called from main.py when a new threat is detected."""
    _threats.appendleft(threat)
    try:
        _sse_queue.put_nowait({"type": "threat", "data": _serialize_threat(threat)})
    except asyncio.QueueFull:
        pass


def push_packet(packet: dict):
    """Called from main.py for each packet."""
    _packets.appendleft(packet)


def update_stats(stats: dict):
    """Called from main.py to update live stats."""
    _stats.update(stats)


def update_blocked(blocked: list):
    """Called from main.py to update blocked IPs list."""
    global _blocked
    _blocked = blocked


# ── REST endpoints ────────────────────────────────────────────────────────────

if FASTAPI_AVAILABLE and app:

    @app.get("/", response_class=HTMLResponse)
    async def index():
        web_path = os.path.join(os.path.dirname(__file__), "..", "web", "index.html")
        with open(web_path, "r") as f:
            return HTMLResponse(f.read())

    @app.get("/api/threats")
    async def get_threats(limit: int = 50):
        return JSONResponse([_serialize_threat(t) for t in list(_threats)[:limit]])

    @app.get("/api/export/json")
    async def export_json():
        import json as _json
        data = [_serialize_threat(t) for t in list(_threats)]
        content = _json.dumps(data, indent=2)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=threats.json"}
        )

    @app.get("/api/export/csv")
    async def export_csv():
        import csv, io
        output = io.StringIO()
        fields = ["time", "type", "severity", "risk_score", "src_ip", "dst_ip", "dst_port", "description", "ai_analyzed"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for t in list(_threats):
            writer.writerow(_serialize_threat(t))
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threats.csv"}
        )

    @app.get("/api/packets")
    async def get_packets(limit: int = 100):
        return JSONResponse([_serialize_packet(p) for p in list(_packets)[:limit]])

    @app.get("/api/stats")
    async def get_stats():
        return JSONResponse(_stats)

    @app.get("/api/blocked")
    async def get_blocked():
        return JSONResponse({"blocked_ips": _blocked, "count": len(_blocked)})

    @app.delete("/api/blocked/{ip}")
    async def unblock(ip: str):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return JSONResponse({"success": False, "error": "Invalid IP address"}, status_code=400)
        from core.blocker import unblock_ip
        success = unblock_ip(ip)
        return JSONResponse({"success": success, "ip": ip})

    @app.get("/api/stream")
    async def sse_stream():
        """Server-Sent Events stream for live updates."""
        async def event_generator():
            # Send current state on connect
            for t in list(_threats)[:20]:
                yield f"data: {json.dumps({'type': 'threat', 'data': _serialize_threat(t)})}\n\n"
            yield f"data: {json.dumps({'type': 'stats', 'data': _stats})}\n\n"

            # Stream new events
            while True:
                try:
                    event = await asyncio.wait_for(_sse_queue.get(), timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat to keep connection alive
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            }
        )


# ── Server runner ─────────────────────────────────────────────────────────────

async def start_server():
    """Start uvicorn in the background (called from main.py)."""
    if not FASTAPI_AVAILABLE:
        print("[!] FastAPI not installed — web dashboard disabled")
        return

    config = uvicorn.Config(
        app,
        host=API_HOST,
        port=API_PORT,
        log_level="error",   # suppress uvicorn access logs
        loop="asyncio",
    )
    server = uvicorn.Server(config)
    print(f"[+] Web dashboard → http://localhost:{API_PORT}")
    await server.serve()


# ── Serializers ───────────────────────────────────────────────────────────────

def _format_time(t: dict) -> str:
    """Return HH:MM:SS — use _time (datetime) or timestamp (ISO string) as fallback."""
    _time = t.get("_time")
    if isinstance(_time, datetime):
        return _time.strftime("%H:%M:%S")
    ts = t.get("timestamp", "")
    if ts:
        try:
            return datetime.fromisoformat(ts).strftime("%H:%M:%S")
        except Exception:
            return ts[:8]
    return datetime.now().strftime("%H:%M:%S")


def _serialize_threat(t: dict) -> dict:
    return {
        "time":        _format_time(t),
        "type":        t.get("ai_threat_name") or t.get("type", "Unknown"),
        "severity":    t.get("ai_severity")    or t.get("severity", "LOW"),
        "risk_score":  t.get("ai_risk_score")  or t.get("risk_score", 0),
        "src_ip":      t.get("src_ip", ""),
        "dst_ip":      t.get("dst_ip", ""),
        "dst_port":    t.get("dst_port", ""),
        "description": t.get("ai_explanation") or t.get("description", ""),
        "ai_analyzed": t.get("ai_analyzed", False),
        "geo":         t.get("geo", {}),
        "vt":          t.get("vt", {}),
        "blocked":     t.get("blocked", False),
    }


def _serialize_packet(p: dict) -> dict:
    return {
        "src_ip":   p.get("src_ip", ""),
        "dst_ip":   p.get("dst_ip", ""),
        "src_port": p.get("src_port", ""),
        "dst_port": p.get("dst_port", ""),
        "protocol": p.get("protocol", ""),
        "length":   p.get("length", 0),
        "flagged":  p.get("_flagged", False),
    }
