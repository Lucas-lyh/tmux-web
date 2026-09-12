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
import re
import shlex
import tempfile
from dataclasses import dataclass
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


def api(path: str, timeout: float = 120) -> str:
    req = urllib.request.Request(BASE + path,
                                 headers={"Authorization": f"Bearer {secret()}"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode()


def api_download(node: str | None, path: str, out: str) -> None:
    """Replace the destination only after a complete, verified transfer."""
    query = {"path": path}
    if node:
        query["node"] = node
    req = urllib.request.Request(
        f"{BASE}/api/download?{urllib.parse.urlencode(query)}",
        headers={"Authorization": f"Bearer {secret()}"},
    )
    destination = os.path.abspath(out)
    temporary = None
    try:
        with urllib.request.urlopen(req, timeout=600) as response:
            value = response.headers.get("Content-Length")
            expected = None if value is None else int(value)
            if expected is not None and expected < 0:
                raise ValueError("negative download Content-Length")
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=os.path.dirname(destination),
                prefix="." + os.path.basename(destination) + ".", suffix=".part",
                delete=False,
            ) as output:
                temporary = output.name
                received = 0
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    received += len(chunk)
                    if expected is not None and received > expected:
                        raise IOError("download exceeds Content-Length")
                    output.write(chunk)
                if expected is not None and received != expected:
                    raise IOError(
                        f"incomplete download: expected {expected} bytes, received {received}"
                    )
                output.flush()
                os.fsync(output.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


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


def send(session: str, text: str, *, timeout: float = 120) -> None:
    api(f"/api/send?{urllib.parse.urlencode({'name': session, 'text': text})}", timeout=timeout)


def capture(session: str, lines: int = 100, *, timeout: float = 120) -> str:
    return api(f"/api/capture?{urllib.parse.urlencode({'name': session, 'lines': lines})}", timeout=timeout)


@dataclass(frozen=True)
class CommandResult:
    output: str
    returncode: int
    truncated: bool = False


def _shell_marker(value: str) -> str:
    # Octal escapes keep the literal marker out of terminal command echo.
    return "".join("\\%03o" % byte for byte in value.encode("ascii"))


def run_result(session: str, cmd: str, timeout: float = 120,
               poll: float = 2.0) -> CommandResult:
    """Execute in the existing POSIX shell and preserve its cwd/environment.

    Output still comes from a 300-line terminal capture, not a persistent log.
    Commands that exit/replace the shell, interactive TUIs, or an already busy
    session cannot provide a completion result. A timeout does not kill a task.
    """
    if timeout <= 0 or poll <= 0:
        raise ValueError("timeout and poll must be positive")
    nonce = os.urandom(12).hex()
    begin, end = "TW_BEGIN_" + nonce, "TW_END_" + nonce
    variable = "__tw_status_" + nonce
    script = (
        "printf '\\n" + _shell_marker(begin) + "\\n'; "
        "eval " + shlex.quote(cmd + "\n") + "; "
        + variable + "=$?; "
        "printf '\\n" + _shell_marker(end) + ":%s\\n' \"$" + variable + "\"; "
        "unset " + variable + "\n"
    )
    deadline = time.monotonic() + timeout
    send(session, script, timeout=timeout)
    pattern = re.compile(re.escape(end) + r":([0-9]{1,3})$")
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("command timed out; it may still be running")
        lines = capture(session, 300, timeout=remaining).splitlines()
        start = None
        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped == begin:
                start = index + 1
            match = pattern.fullmatch(stripped)
            if match:
                output = lines[start if start is not None else 0:index]
                if output and output[-1] == "":
                    output.pop()  # The separator inserted before the end marker.
                return CommandResult("\n".join(output),
                                     int(match[1]), start is None)
        time.sleep(min(poll, max(0, deadline - time.monotonic())))


def run(session: str, cmd: str, timeout: float = 120, poll: float = 2.0) -> str:
    """Backward-compatible text interface; run_result also exposes exit status."""
    return run_result(session, cmd, timeout, poll).output


def main() -> int:
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
        result = run_result(args.name, args.command, args.timeout)
        print(result.output)
        return result.returncode
    elif args.cmd == "upload":
        print(asyncio.run(upload(args.local, args.node)))
    elif args.cmd == "download":
        api_download(args.node, args.path, args.out)
        print("downloaded ->", args.out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
