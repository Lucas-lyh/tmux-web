#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tmux-web client: drive sessions on the hub and child nodes from the CLI.

Wraps the server.py HTTP/WS API (/api/new, /api/send, /api/capture,
/api/download, /ws-upload, ...) so agents don't have to re-implement
the poll/marker loop every time.

Auth: reads the node secret (.node-secret next to this script) and uses it
as a Bearer token, which the server accepts for all /api and /ws-upload
calls (server.py:request_authed). Note this secret is also the node-join token,
so it grants full access — treat this script as operator tooling.

Environment:
  TMUX_WEB_BASE   server URL          (default http://127.0.0.1:59999)
  TMUX_WEB_SECRET secret file path    (default .node-secret next to script)

Examples:
  python3 client.py sessions
  python3 client.py new gpu1:train
  python3 client.py run gpu1:train "nvidia-smi" --timeout 60
  python3 client.py capture demo 100
  python3 client.py upload ./big.bin --node gpu1
  python3 client.py download /tmp/result.bin ./result.bin --node gpu1
"""
import argparse
import asyncio
import json
import os
import sys
import time
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("TMUX_WEB_BASE", "http://127.0.0.1:59999").rstrip("/")
SECRET_FILE = os.environ.get("TMUX_WEB_SECRET", os.path.join(BASE_DIR, ".node-secret"))
WS = BASE.replace("http://", "ws://").replace("https://", "wss://")

CHUNK = 4 * 1024 * 1024


def secret() -> str:
    with open(SECRET_FILE) as f:
        return f.read().strip()


def api(path: str) -> str:
    req = urllib.request.Request(BASE + path,
                                 headers={"Authorization": f"Bearer {secret()}"})
    return urllib.request.urlopen(req, timeout=120).read().decode()


def api_download(node: str | None, path: str, out: str) -> None:
    q = {"path": path}
    if node:
        q["node"] = node
    url = f"{BASE}/api/download?{urllib.parse.urlencode(q)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {secret()}"})
    with urllib.request.urlopen(req, timeout=600) as r, open(out, "wb") as f:
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            f.write(chunk)


async def upload(local: str, node: str | None) -> str:
    import websockets
    size = os.path.getsize(local)
    name = os.path.basename(local)
    url = f"{WS}/ws-upload" + (f"?node={urllib.parse.quote(node)}" if node else "")
    async with websockets.connect(url, additional_headers={"Authorization": f"Bearer {secret()}"},
                                  max_size=None, open_timeout=60) as ws:
        await ws.send(json.dumps({"name": name, "size": size}))
        sent = 0
        with open(local, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                await ws.send(chunk)
                sent += len(chunk)
                print(f"\r{sent/1e6:.0f}/{size/1e6:.0f} MB", end="", flush=True)
        resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=600))
        print()
        if not resp.get("ok"):
            raise RuntimeError(resp)
        return resp["path"]


def send(session: str, text: str) -> None:
    api(f"/api/send?{urllib.parse.urlencode({'name': session, 'text': text})}")


def capture(session: str, lines: int = 100) -> str:
    return api(f"/api/capture?{urllib.parse.urlencode({'name': session, 'lines': lines})}")


def run(session: str, cmd: str, timeout: int = 120, poll: float = 2.0) -> str:
    """Run a command, detect completion via a unique marker on its own line,
    and return the output before it.

    Limits: completion is judged from `capture` (last 300 lines, ANSI-stripped),
    so output longer than that is truncated, and full-screen TUI apps
    (vim/less/htop) that redraw the screen can confuse the marker check.
    """
    marker = "TW_DONE_" + os.urandom(4).hex()
    send(session, cmd + f";echo {marker}\n")
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(poll)
        lines = capture(session, 300).splitlines()
        for i, ln in enumerate(lines):
            if ln.strip() == marker:
                return "\n".join(lines[:i])
    raise TimeoutError(f"command not finished within {timeout}s: {cmd[:80]}")


def main() -> None:
    p = argparse.ArgumentParser(prog="client.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("sessions", help="list all sessions (JSON)")

    sp = sub.add_parser("new", help="create session (use node:name for a child node)")
    sp.add_argument("name")

    sp = sub.add_parser("kill", help="kill session")
    sp.add_argument("name")

    sp = sub.add_parser("send", help="type text into a session (\\n = Enter)")
    sp.add_argument("name")
    sp.add_argument("text")

    sp = sub.add_parser("capture", help="print last N lines of output")
    sp.add_argument("name")
    sp.add_argument("lines", nargs="?", type=int, default=100)

    sp = sub.add_parser("run", help="run a command and print its output (marker polling)")
    sp.add_argument("name")
    sp.add_argument("command")
    sp.add_argument("--timeout", type=int, default=120)

    sp = sub.add_parser("upload", help="upload a file to hub or node temp dir")
    sp.add_argument("local")
    sp.add_argument("--node")

    sp = sub.add_parser("download", help="download a file from hub or node")
    sp.add_argument("path")
    sp.add_argument("out")
    sp.add_argument("--node", help="node name (omit for a hub-local path)")

    args = p.parse_args()

    if args.cmd == "sessions":
        print(api("/api/sessions"))
    elif args.cmd == "new":
        print(api(f"/api/new?name={urllib.parse.quote(args.name)}"))
    elif args.cmd == "kill":
        print(api(f"/api/kill?name={urllib.parse.quote(args.name)}"))
    elif args.cmd == "send":
        send(args.name, args.text)
    elif args.cmd == "capture":
        print(capture(args.name, args.lines))
    elif args.cmd == "run":
        print(run(args.name, args.command, args.timeout))
    elif args.cmd == "upload":
        print(asyncio.run(upload(args.local, args.node)))
    elif args.cmd == "download":
        api_download(args.node, args.path, args.out)
        print("downloaded ->", args.out)


if __name__ == "__main__":
    main()
