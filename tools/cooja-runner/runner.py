#!/usr/bin/env python3
import asyncio
import os
import json
from collections import deque
from typing import Deque, List, Optional

from fastapi import FastAPI, HTTPException
import aiohttp
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Cooja Runner")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Path to cooja workspace. Prefer env override so the container can point at a mounted repo.
COOJA_DIR = os.environ.get(
    "COOJA_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "simulation", "contiki-ng", "tools", "cooja")),
)

_proc: asyncio.subprocess.Process | None = None
_log_buffer: Deque[str] = deque(maxlen=2000)
_reader_task: asyncio.Task | None = None
_http_session: Optional[aiohttp.ClientSession] = None


async def _maybe_forward_telemetry(text: str) -> None:
    # detect lines like: COAP_SEND <MAC> <JSON>
    if "COAP_SEND " not in text:
        return
    try:
        # line may be prefixed with [OUT] etc.
        idx = text.index("COAP_SEND ")
        payload_part = text[idx + len("COAP_SEND "):].strip()
        # split first token (mac) and the rest (json)
        mac, rest = payload_part.split(" ", 1)
        data = json.loads(rest)
    except Exception:
        _log_buffer.append(f"[SYSTEM] Failed to parse COAP_SEND line: {text}")
        return

    api_url = os.environ.get("API_URL", "http://localhost:8000")
    url = f"{api_url.rstrip('/')}/iot/telemetry"
    body = {
        "device_mac": mac,
        "payload": json.dumps(data),
        "message_type": "cooja",
        "path": "/telemetry",
        "source_ip": "cooja_sim",
    }

    global _http_session
    try:
        if _http_session is None:
            _http_session = aiohttp.ClientSession()
        async with _http_session.post(url, json=body, timeout=5) as resp:
            if resp.status >= 200 and resp.status < 300:
                _log_buffer.append(f"[SYSTEM] Forwarded telemetry for {mac}")
            else:
                text_resp = await resp.text()
                _log_buffer.append(f"[SYSTEM] Telemetry forward failed {resp.status}: {text_resp}")
    except Exception as e:
        _log_buffer.append(f"[SYSTEM] Telemetry forward error: {e}")


async def _read_stream(stream: asyncio.StreamReader, name: str) -> None:
    while True:
        line = await stream.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip("\n")
        _log_buffer.append(f"[{name}] {text}")
        # spawn forwarding task if the line contains COAP_SEND
        if "COAP_SEND " in text:
            asyncio.create_task(_maybe_forward_telemetry(text))


async def _attach_reader(proc: asyncio.subprocess.Process) -> None:
    global _reader_task
    stdout = proc.stdout
    stderr = proc.stderr
    async def reader():
        await asyncio.gather(_read_stream(stdout, "OUT"), _read_stream(stderr, "ERR"))

    _reader_task = asyncio.create_task(reader())


@app.post("/start")
async def start_cooja(gui: bool = True, csc_path: Optional[str] = None):
    """Start Cooja. If gui=False will run headless (--no-gui)."""
    global _proc
    if _proc and _proc.returncode is None:
        raise HTTPException(status_code=400, detail="Cooja already running")

    if not os.path.isdir(COOJA_DIR):
        _log_buffer.append(f"[SYSTEM] Cooja directory not found: {COOJA_DIR}")
        raise HTTPException(status_code=500, detail=f"Cooja directory not found: {COOJA_DIR}")

    # Search for a .csc file under /workspace/simulation or /workspace if not provided
    if not csc_path:
        workspace_dir = "/workspace"
        sim_dir = os.path.join(workspace_dir, "simulation")
        if os.path.isdir(sim_dir):
            csc_files = [f for f in os.listdir(sim_dir) if f.endswith(".csc")]
            if csc_files:
                csc_path = os.path.join(sim_dir, csc_files[0])
        if not csc_path and os.path.isdir(workspace_dir):
            csc_files = [f for f in os.listdir(workspace_dir) if f.endswith(".csc")]
            if csc_files:
                csc_path = os.path.join(workspace_dir, csc_files[0])

    cmd = ["./gradlew", "run"]
    args_list = []
    if not gui:
        args_list.append("--no-gui")
    if csc_path:
        args_list.append(csc_path)

    if args_list:
        cmd.append(f"--args={' '.join(args_list)}")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=COOJA_DIR,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    _log_buffer.append(f"[SYSTEM] Started Cooja (pid={proc.pid}) gui={gui} csc_path={csc_path}")
    await _attach_reader(proc)

    _proc = proc
    return {"status": "started", "pid": proc.pid}


@app.post("/stop")
async def stop_cooja():
    global _proc, _reader_task
    if not _proc:
        return {"status": "not running"}

    try:
        _proc.terminate()
        await asyncio.wait_for(_proc.wait(), timeout=10.0)
    except asyncio.TimeoutError:
        _proc.kill()
        await _proc.wait()

    _log_buffer.append("[SYSTEM] Stopped Cooja")
    _proc = None

    if _reader_task:
        try:
            _reader_task.cancel()
        except Exception:
            pass
        _reader_task = None

    return {"status": "stopped"}


@app.get("/status")
async def status():
    running = _proc is not None and _proc.returncode is None
    return {"running": running, "pid": getattr(_proc, "pid", None)}


@app.get("/logs")
async def logs(tail: int = 200) -> List[str]:
    tail = max(1, min(2000, int(tail)))
    return list(_log_buffer)[-tail:]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5001)
