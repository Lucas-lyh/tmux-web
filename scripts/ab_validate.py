#!/usr/bin/env python3
"""Run isolated A/B contract checks and real historical-node compatibility.

Example (the interpreter must have the project's normal server dependencies):
  python scripts/ab_validate.py --output /tmp/tmux-web-ab-report

No existing service is contacted. Every fixture has a temporary source tree,
state directory, HOME, tmux socket, upload directory and random loopback port.
The harness itself uses only the standard library. Historical node scripts run
unchanged, apart from a launcher overriding their temporary upload directory.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse

DEFAULT_BASELINE = "979cc32"
NODE_REFS = (
    ("query-token", "017c486", False),
    ("bearer", "b02d477", False),
    ("noise", "979cc32", True),
)
PRODUCTION = (
    "server.py", "node.py", "client.py", "http_frontend.py",
    "token_usage.py", "requirements.txt", "hub", "static",
)
HUB_LAUNCHER = r"""
import asyncio, os, pathlib, sys
sys.path.insert(0, os.environ["AB_SOURCE"])
import server
state = pathlib.Path(os.environ["AB_STATE"]).resolve()
assert str(state).startswith("/tmp/")
server.HOST = "127.0.0.1"
server.PORT = int(os.environ["AB_PORT"])
server.AUTH_FILE = str(state / ".auth.json")
server.TOKEN_FILE = str(state / ".tokens.json")
server.NODE_SECRET_FILE = str(state / ".node-secret")
server.PAGES_DIR = str(state / "pages")
server.UPLOAD_DIR = str(state / "uploads")
assert server.PORT != 59999
asyncio.run(server.main())
"""
NODE_LAUNCHER = r"""
import asyncio, importlib.util, os, pathlib, sys
script = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("ab_fixture_node", script)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.UPLOAD_DIR = os.environ["AB_NODE_UPLOADS"]
assert str(pathlib.Path(module.UPLOAD_DIR).resolve()).startswith("/tmp/")
sys.argv = [str(script)] + sys.argv[2:]
asyncio.run(module.main())
"""


def git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=False
    )
    if result.returncode:
        # Git stderr can contain user-specific repository/remote configuration.
        raise RuntimeError("git " + args[0] + " failed; required local history may be missing")
    return result.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def copy_candidate(repo, destination):
    destination.mkdir()
    copied = {}
    for item in PRODUCTION:
        source = repo / item
        if not source.exists():
            continue
        paths = sorted(source.rglob("*")) if source.is_dir() else [source]
        for path in paths:
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            if item == "hub" and path.suffix != ".py":
                continue
            if any(part.startswith('.') for part in path.relative_to(repo).parts):
                continue
            if path.is_symlink():
                raise RuntimeError("candidate production symlinks are not supported")
            relative = path.relative_to(repo)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            data = path.read_bytes()
            target.write_bytes(data)
            copied[str(relative)] = sha(data)
    if not (destination / "server.py").is_file():
        raise RuntimeError("candidate server.py is missing")
    return copied


def export_baseline(repo, ref, destination):
    archive = git(repo, "archive", "--format=tar", ref)
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar:
            path = Path(member.name)
            if not path.parts or path.parts[0] not in PRODUCTION:
                continue
            if any(part.startswith('.') for part in path.parts):
                continue
            if path.parts[0] == 'hub' and member.isfile() and path.suffix != '.py':
                continue
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("unsafe archive path")
            if member.isdir():
                (destination / path).mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target = destination / path
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source:
                    target.write_bytes(source.read())
            else:
                raise RuntimeError("non-regular archive entry is not supported")


def isolated_env(state, bindir):
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("TMUX") or key.startswith("AB_") or key in (
            "BASH_ENV", "ENV", "PROMPT_COMMAND", "PYTHONPATH", "PYTHONSTARTUP", "CDPATH"
        ):
            env.pop(key, None)
    home = state / "home"
    home.mkdir(parents=True, exist_ok=True)
    tmpdir = state / "tmp"
    tmpdir.mkdir()
    env.update(
        HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
        XDG_CACHE_HOME=str(home / ".cache"), CODEX_HOME=str(home / ".codex"),
        TMUX_TMPDIR=str(state / "tmux-tmp"), TMPDIR=str(tmpdir),
        PATH=str(bindir) + os.pathsep + os.environ.get("PATH", os.defpath),
        LANG="C.UTF-8", TERM="xterm-256color", PS1="", PS2="",
        PYTHONDONTWRITEBYTECODE="1",
    )
    Path(env["TMUX_TMPDIR"]).mkdir()
    return env


def private_executable(path, content):
    path.write_text(content, encoding="utf-8")
    path.chmod(0o700)


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    if port == 59999:
        raise RuntimeError("refusing the production port")
    return port


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


class FixtureWebSocket:
    """Minimal RFC6455 fixture client; connects only to an owned hub."""

    def __init__(self, hub, path):
        if hub.port == 59999:
            raise RuntimeError("refusing the production port")
        self.sock = socket.create_connection(("127.0.0.1", hub.port), timeout=hub.timeout)
        self.sock.settimeout(hub.timeout)
        self.reader = self.sock.makefile("rb")
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = (
            "GET " + path + " HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + str(hub.port) + "\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n"
            "Authorization: Bearer " + hub.token + "\r\n\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        status = self.reader.readline()
        headers = {}
        while True:
            line = self.reader.readline()
            if line in (b"\r\n", b""):
                break
            name, value = line.decode("latin1").split(":", 1)
            headers[name.lower()] = value.strip()
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        if not status.startswith(b"HTTP/1.1 101 ") or headers.get("sec-websocket-accept") != expected:
            self.close()
            raise AssertionError("fixture WebSocket handshake failed")

    def send(self, payload, opcode=None):
        if isinstance(payload, str):
            payload = payload.encode()
            opcode = 1 if opcode is None else opcode
        else:
            opcode = 2 if opcode is None else opcode
        size = len(payload)
        head = bytes([0x80 | opcode])
        if size < 126:
            head += bytes([0x80 | size])
        elif size < 65536:
            head += bytes([0x80 | 126]) + struct.pack("!H", size)
        else:
            head += bytes([0x80 | 127]) + struct.pack("!Q", size)
        mask = secrets.token_bytes(4)
        self.sock.sendall(head + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))

    def read_exact(self, size):
        data = self.reader.read(size)
        if len(data) != size:
            raise ConnectionError("fixture WebSocket closed early")
        return data

    def recv(self):
        chunks = []
        initial = None
        while True:
            first, second = self.read_exact(2)
            opcode = first & 15
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", self.read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.read_exact(8))[0]
            if length > 4 * 1024 * 1024:
                raise AssertionError("fixture WebSocket message exceeds safety limit")
            mask = self.read_exact(4) if second & 128 else None
            data = self.read_exact(length)
            if mask:
                data = bytes(v ^ mask[i % 4] for i, v in enumerate(data))
            if opcode == 8:
                raise ConnectionError("fixture WebSocket received close")
            if opcode == 9:
                self.send(data, 10)
                continue
            if opcode == 10:
                continue
            if opcode in (1, 2):
                initial = opcode
            chunks.append(data)
            if first & 128:
                result = b"".join(chunks)
                return result.decode() if initial == 1 else result

    def close(self):
        with contextlib.suppress(Exception):
            self.send(struct.pack("!H", 1000), 8)
        with contextlib.suppress(Exception):
            self.reader.close()
        with contextlib.suppress(Exception):
            self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


class HubFixture:
    def __init__(self, name, source, root, python, timeout, sensitive):
        self.name, self.source, self.python, self.timeout = name, source, python, timeout
        self.state = root / (name + "-state")
        self.state.mkdir(mode=0o700)
        self.bindir = self.state / "bin"
        self.bindir.mkdir()
        self.socket = self.state / "tmux.sock"
        self.port = available_port()
        self.password = secrets.token_urlsafe(24)
        sensitive.append(self.password)
        self.sensitive = sensitive
        self.token = ""
        self.cookie = ""
        self.process = None
        self.nodes = []
        self.real_tmux = shutil.which("tmux")
        if not self.real_tmux:
            raise RuntimeError("tmux is required")
        private_executable(
            self.bindir / "tmux",
            "#!/bin/sh\nexec " + shlex.quote(self.real_tmux) +
            " -S " + shlex.quote(str(self.socket)) + ' "$@"\n',
        )
        private_executable(
            self.bindir / "isolated-shell", "#!/bin/sh\nexec /bin/bash --noprofile --norc\n"
        )
        self.env = isolated_env(self.state, self.bindir)
        self.env.update(
            AB_SOURCE=str(source), AB_STATE=str(self.state), AB_PORT=str(self.port),
            TMUX_WEB_HOST="127.0.0.1", TMUX_WEB_PORT=str(self.port),
            TMUX_WEB_PASSWORD=self.password, TMUX_WEB_STATE_DIR=str(self.state),
            TMUX_WEB_TMUX_SOCKET=str(self.socket),
            TMUX_WEB_COOKIE_NAME="tmux_web_b_token" if name == "B" else "tmux_web_token",
            SHELL=str(self.bindir / "isolated-shell"),
        )
        self.launcher = self.state / "hub-launcher.py"
        self.launcher.write_text(HUB_LAUNCHER)
        self.node_launcher = self.state / "node-launcher.py"
        self.node_launcher.write_text(NODE_LAUNCHER)
        config = self.state / "tmux.conf"
        config.write_text(
            "set -g default-shell /bin/bash\n"
            "set -g default-command '/bin/bash --noprofile --norc'\n"
            "set -g status off\nset -g history-limit 2000\n"
        )
        # A keeper avoids accidental daemon exit while test sessions are removed.
        self.tmux("-f", str(config), "new-session", "-d", "-s", "__ab_keeper")
        actual = self.tmux("display-message", "-p", "-t", "__ab_keeper", "#{socket_path}").strip()
        if actual != str(self.socket):
            raise AssertionError("tmux socket isolation failed")
        self.start()

    def tmux(self, *args):
        process = subprocess.run(
            [self.real_tmux, "-S", str(self.socket), *args],
            env=self.env, cwd=self.state, text=True, capture_output=True, timeout=10,
        )
        if process.returncode:
            raise RuntimeError("isolated tmux operation failed: " + args[0])
        return process.stdout

    def start(self):
        self.process = subprocess.Popen(
            [self.python, "-B", str(self.launcher)], env=self.env, cwd=self.source,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(self.name + " hub exited during isolated startup")
            try:
                status, _, _ = self.request("/", auth=False)
                secret_file = self.state / ".node-secret"
                if status == 200 and secret_file.exists():
                    self.token = secret_file.read_text().strip()
                    self.sensitive.append(self.token)
                    return
            except (ConnectionError, OSError):
                pass
            time.sleep(0.05)
        raise TimeoutError(self.name + " hub did not become ready")

    def restart(self):
        old_pid = self.process.pid
        stop_process(self.process)
        self.start()
        if self.process.pid == old_pid:
            raise AssertionError("fixture hub did not restart")

    def request(self, path, query=None, auth=True, cookie=None):
        if self.port == 59999 or not path.startswith("/") or path.startswith("//"):
            raise RuntimeError("refusing non-fixture request")
        if query:
            path += "?" + urllib.parse.urlencode(query)
        headers = {}
        if auth:
            headers["Authorization"] = "Bearer " + self.token
        if cookie is not None:
            headers["Cookie"] = cookie
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        try:
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def api(self, path, **query):
        status, _, body = self.request(path, query)
        if status != 200:
            raise AssertionError(path + " returned status " + str(status))
        return body

    def node_names(self):
        return {entry["name"]: entry for entry in json.loads(self.api("/api/nodes"))["nodes"]}

    def await_node(self, name):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if name in self.node_names():
                return
            time.sleep(0.1)
        raise TimeoutError("historical node did not connect: " + name)

    def await_capture(self, session, marker):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            body = self.api("/api/capture", name=session, lines=200).decode()
            if marker in (line.strip() for line in body.splitlines()):
                return {"status": 200, "marker": marker}
            time.sleep(0.1)
        raise TimeoutError("expected terminal output not observed")

    def upload(self, data, node=None):
        path = "/ws-upload"
        if node:
            path += "?" + urllib.parse.urlencode({"node": node})
        with FixtureWebSocket(self, path) as ws:
            ws.send(json.dumps({"name": "contract.bin", "size": len(data)}))
            for start in range(0, len(data), 32768):
                ws.send(data[start:start + 32768])
            result = json.loads(ws.recv())
        if not result.get("ok"):
            raise AssertionError("fixture upload rejected")
        uploaded = Path(result["path"]).resolve()
        expected_root = self.state / "uploads" if node is None else self.state / ("node-" + node) / "uploads"
        if not uploaded.is_relative_to(expected_root):
            raise AssertionError("upload escaped its fixture state directory")
        status, _, received = self.request(
            "/api/download", {"path": str(uploaded), **({"node": node} if node else {})}
        )
        if status != 200 or received != data:
            raise AssertionError("fixture upload/download bytes differ")
        return {"status": status, "size": len(received), "sha256": sha(received), "isolated": True}

    def start_node(self, label, script, encrypted):
        name = "ab-" + label
        directory = self.state / ("node-" + name)
        directory.mkdir()
        uploads = directory / "uploads"
        uploads.mkdir()
        env = dict(self.env)
        env["AB_NODE_UPLOADS"] = str(uploads)
        env["TMUX_WEB_NODE_TOKEN"] = self.token
        env["TMUX_WEB_PORTAL_URL"] = ""
        env["TMUX_WEB_PORTAL_USER"] = ""
        env["TMUX_WEB_PORTAL_PASS"] = ""
        args = [
            self.python, "-B", "-S", str(self.node_launcher), str(script),
            "--server", "ws://127.0.0.1:" + str(self.port) + "/ws-node",
            "--name", name,
        ]
        if label == "bearer":
            args.append("--allow-insecure-ws")
        process = subprocess.Popen(
            args, cwd=directory, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
        self.nodes.append((name, process))
        self.await_node(name)
        actual_encrypted = bool(self.node_names()[name].get("encrypted"))
        if actual_encrypted != encrypted:
            raise AssertionError("historical node negotiated the wrong transport")
        return name, process

    def close(self):
        # Only explicitly owned node/session names are ever addressed here.
        if self.process is not None and self.process.poll() is None:
            for name, _ in self.nodes:
                with contextlib.suppress(Exception):
                    self.request("/api/kill", {"name": name + ":contract"})
        for _, process in self.nodes:
            stop_process(process)
        stop_process(self.process)
        with contextlib.suppress(Exception):
            self.tmux("kill-server")


class Report:
    def __init__(self, metadata, sensitive):
        self.metadata = metadata
        self.sensitive = sensitive
        self.cases = []
        self.observations = {"A": {}, "B": {}}

    def record(self, name, operation, *, group, side=None):
        try:
            observation = operation()
            self.cases.append({"name": name, "group": group, "side": side, "status": "passed"})
            if side:
                self.observations[side][name] = observation
            return observation
        except Exception as exc:
            detail = type(exc).__name__ + ": " + str(exc)
            self.cases.append({
                "name": name, "group": group, "side": side, "status": "failed",
                "detail": self.redact(detail),
            })
            return None

    def redact(self, value):
        for secret in sorted(set(self.sensitive), key=len, reverse=True):
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value

    def compare(self):
        approved = {"offline.capture", "offline.send", "offline.kill"}
        for name in sorted(set(self.observations["A"]) | set(self.observations["B"])):
            a = self.observations["A"].get(name)
            b = self.observations["B"].get(name)
            if a is None or b is None:
                status = "failed"
            elif a == b:
                status = "passed"
            elif name in approved and b.get("status") == 404:
                status = "approved_fix"
            else:
                status = "failed"
            self.cases.append({
                "name": name, "group": "A/B differential", "status": status,
                "baseline": a, "candidate": b,
            })

    def write(self, output):
        failed = sum(case["status"] == "failed" for case in self.cases)
        result = {
            **self.metadata,
            "status": "failed" if failed else "passed",
            "summary": {
                "passed": sum(case["status"] == "passed" for case in self.cases),
                "approved_fix": sum(case["status"] == "approved_fix" for case in self.cases),
                "failed": failed,
            },
            "cases": self.cases,
        }
        output.mkdir(parents=True, exist_ok=True)
        text = self.redact(json.dumps(result, ensure_ascii=False, indent=2))
        (output / "report.json").write_text(text + "\n", encoding="utf-8")
        lines = [
            "# tmux-web isolated A/B validation", "",
            "Result: **" + result["status"] + "**", "",
            "- Baseline: `" + self.metadata.get("baseline_commit", "unavailable") + "`",
            "- Candidate HEAD: `" + self.metadata.get("candidate_commit", "unavailable") + "`",
            "- Candidate files: snapshot of the working tree, including hub/ and static/.",
            "- Production service: never contacted; fixture ports exclude 59999.",
            "- Fixtures: private source, state, HOME, upload paths and tmux sockets; removed on exit.",
            "", "| Group | Side | Scenario | Result |", "| --- | --- | --- | --- |",
        ]
        for case in self.cases:
            lines.append("| " + " | ".join([
                case["group"], case.get("side") or "—", case["name"], case["status"]
            ]) + " |")
        lines += ["", "See report.json for normalized observations and failure details.", ""]
        (output / "report.md").write_text(self.redact("\n".join(lines)), encoding="utf-8")
        return 1 if failed else 0


def text_response(hub, path, query=None, auth=True):
    status, _, body = hub.request(path, query, auth=auth)
    return {"status": status, "body": body.decode("utf-8", "replace")}


def require_status(value, expected=200):
    if value["status"] != expected:
        raise AssertionError("unexpected HTTP status " + str(value["status"]))
    return value


def print_command(marker):
    # No literal marker in the echoed command, useful for WebSocket assertions.
    escaped = "".join("\\%03o" % byte for byte in marker.encode())
    return "printf '" + escaped + "\\n'\n"


def normal_suite(hub, report):
    def record(name, operation):
        return report.record(name, operation, group="HTTP contract", side=hub.name)

    record("auth.unauthorized", lambda: require_status(
        text_response(hub, "/api/sessions", auth=False), 401))
    record("html.login", lambda: html_observation(hub, False))

    def login():
        status, headers, body = hub.request(
            "/api/login", {"password": hub.password}, auth=False
        )
        if status != 200:
            raise AssertionError("fixture login failed")
        raw_cookie = headers.get("Set-Cookie", "")
        hub.cookie = raw_cookie.split(";", 1)[0]
        if not hub.cookie or "=" not in hub.cookie:
            raise AssertionError("fixture login did not issue a cookie")
        report.sensitive.append(hub.cookie.partition("=")[2])
        cookie_status, _, _ = hub.request("/api/sessions", auth=False, cookie=hub.cookie)
        if cookie_status != 200:
            raise AssertionError("fixture cookie authentication failed")
        return {"status": status, "body": body.decode(), "cookie_auth": cookie_status}

    record("auth.login", login)

    def credential_isolation():
        names = (".auth.json", ".tokens.json", ".node-secret")
        if any((hub.source / name).exists() for name in names):
            raise AssertionError("source snapshot contains runtime credentials")
        if not all((hub.state / name).is_file() for name in names):
            raise AssertionError("fixture credentials are not confined to its state directory")
        return {"source_credentials_absent": True, "fixture_state_credentials_present": True}

    record("auth.credential_isolation", credential_isolation)
    record("html.dashboard", lambda: html_observation(hub, True))
    record("local.new", lambda: require_status(text_response(hub, "/api/new", {"name": "ab-local"})))
    record("local.send", lambda: require_status(text_response(
        hub, "/api/send", {"name": "ab-local", "text": print_command("AB_LOCAL_READY")})))
    record("local.capture", lambda: hub.await_capture("ab-local", "AB_LOCAL_READY"))

    def attach():
        data = b""
        with FixtureWebSocket(hub, "/ws?session=ab-local") as ws:
            ws.send(json.dumps({"type": "resize", "cols": 100, "rows": 30}))
            ws.send(print_command("AB_ATTACH_READY").replace("\n", "\r").encode())
            deadline = time.monotonic() + hub.timeout
            while b"AB_ATTACH_READY" not in data and time.monotonic() < deadline:
                message = ws.recv()
                data += message.encode() if isinstance(message, str) else message
        if b"AB_ATTACH_READY" not in data:
            raise AssertionError("fixture tmux attach output missing")
        hub.await_capture("ab-local", "AB_ATTACH_READY")
        # The actual daemon, not only the environment, must use our socket.
        if hub.tmux("display-message", "-p", "-t", "ab-local", "#{socket_path}").strip() != str(hub.socket):
            raise AssertionError("tmux attach did not use its fixture")
        return {"attached": True, "isolated_socket": True}

    record("local.attach", attach)
    record("files.local", lambda: hub.upload(bytes(range(256)) * 257))

    def page():
        directory = hub.state / "pages"
        directory.mkdir(exist_ok=True)
        content = b"<!doctype html><title>AB contract</title><p>fixture only</p>"
        (directory / "contract.html").write_bytes(content)
        pages = json.loads(hub.api("/api/pages"))
        match = next((p for p in pages if p["name"] == "contract.html"), None)
        if match is None or match["title"] != "AB contract":
            raise AssertionError("fixture page was not listed")
        status, _, body = hub.request("/pages/contract.html")
        if body != content:
            raise AssertionError("fixture page bytes changed")
        return {"status": status, "sha256": sha(body), "title": match["title"]}

    record("pages.publish", page)
    record("local.kill", lambda: require_status(text_response(hub, "/api/kill", {"name": "ab-local"})))
    # With A, 'offline:0' resolves to local tmux session offline, window 0.
    # B intentionally rejects disconnected node prefixes before calling tmux.
    hub.api("/api/new", name="offline")
    for action in ("capture", "send", "kill"):
        query = {"name": "offline:0"}
        if action == "send":
            query["text"] = print_command("AB_OFFLINE_GUARD")
        def offline(action=action, query=query):
            status, _, _ = hub.request("/api/" + action, query)
            if hub.name == "B" and status != 404:
                raise AssertionError("B must reject disconnected node targets")
            return {"status": status}
        record("offline." + action, offline)
    hub.request("/api/kill", {"name": "offline"})


def html_observation(hub, auth):
    status, _, body = hub.request("/", auth=auth)
    if status != 200:
        raise AssertionError("fixture HTML unavailable")
    return {"status": status, "size": len(body), "sha256": sha(body)}


def node_suite(hub, report, label, script, encrypted, differential=False):
    name = "ab-" + label
    session = name + ":contract"
    prefix = "node." + label + "."
    side = hub.name if differential else None
    group = "historical node compatibility"

    def record(action, operation):
        return report.record(prefix + action, operation, group=group, side=side)

    def start():
        hub.start_node(label, script, encrypted)
        return {"connected": True, "encrypted": encrypted}

    if record("connect", start) is None:
        return
    record("new", lambda: require_status(text_response(hub, "/api/new", {"name": session})))
    record("send", lambda: require_status(text_response(
        hub, "/api/send", {"name": session, "text": print_command("AB_NODE_READY")})))
    record("capture", lambda: hub.await_capture(session, "AB_NODE_READY"))
    record("files", lambda: hub.upload(bytes(range(251)) * 263, node=name))

    def reconnect():
        process = next(process for n, process in hub.nodes if n == name)
        original_pid = process.pid
        hub.restart()
        hub.await_node(name)
        if process.poll() is not None or process.pid != original_pid:
            raise AssertionError("node process did not survive fixture hub restart")
        hub.await_capture(session, "AB_NODE_READY")
        hub.api("/api/send", name=session, text=print_command("AB_RECONNECTED"))
        hub.await_capture(session, "AB_RECONNECTED")
        return {"same_node_process": True, "session_preserved": True, "command_after_reconnect": True}

    record("reconnect", reconnect)
    record("kill", lambda: require_status(text_response(hub, "/api/kill", {"name": session})))
    for n, process in hub.nodes:
        if n == name:
            stop_process(process)


def cookie_isolation(a, b):
    a_name = a.cookie.partition("=")[0]
    b_name = b.cookie.partition("=")[0]
    if a_name != "tmux_web_token" or b_name != "tmux_web_b_token":
        raise AssertionError("A and B did not use independent expected cookie names")
    if a.request("/api/sessions", auth=False, cookie=b.cookie)[0] != 401:
        raise AssertionError("A accepted B's cookie")
    if b.request("/api/sessions", auth=False, cookie=a.cookie)[0] != 401:
        raise AssertionError("B accepted A's cookie")
    combined = a.cookie + "; " + b.cookie
    if any(h.request("/api/sessions", auth=False, cookie=combined)[0] != 200 for h in (a, b)):
        raise AssertionError("A/B cookies cannot coexist in the same browser")
    return {"different_names": True, "cross_rejected": True, "coexist": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable, help="interpreter with existing server dependencies")
    parser.add_argument("--timeout", type=float, default=25)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if not output.is_relative_to(Path("/tmp")) or output == Path("/tmp"):
        parser.error("--output must be a subdirectory of /tmp")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    repo = args.candidate.resolve()
    sensitive = []
    report = Report({
        "baseline_ref": args.baseline, "candidate_root": str(repo),
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "isolation": "temporary-source/state/HOME/tmux-socket; owned loopback ports; no production requests",
    }, sensitive)
    fixtures = []
    try:
        report.metadata["baseline_commit"] = git(repo, "rev-parse", "--verify", args.baseline + "^{commit}").decode().strip()
        report.metadata["candidate_commit"] = git(repo, "rev-parse", "HEAD").decode().strip()
        node_sources = {}
        for label, ref, encrypted in NODE_REFS:
            commit = git(repo, "rev-parse", "--verify", ref + "^{commit}").decode().strip()
            node_sources[label] = (git(repo, "show", commit + ":node.py"), encrypted)
        report.metadata["historical_node_refs"] = {label: ref for label, ref, _ in NODE_REFS}
        with tempfile.TemporaryDirectory(prefix="tmux-web-ab-", dir="/tmp") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            a_source, b_source = root / "A-source", root / "B-source"
            export_baseline(repo, args.baseline, a_source)
            report.metadata["candidate_files_sha256"] = copy_candidate(repo, b_source)
            scripts = {}
            for label, (data, _) in node_sources.items():
                scripts[label] = root / ("node-" + label + ".py")
                scripts[label].write_bytes(data)
            try:
                for name, source in (("A", a_source), ("B", b_source)):
                    # Register before initialization so partial startup is cleaned too.
                    hub = HubFixture.__new__(HubFixture)
                    fixtures.append(hub)
                    HubFixture.__init__(hub, name, source, root, args.python, args.timeout, sensitive)
                    print("Fixture " + name + ": isolated startup ready", flush=True)
                    normal_suite(hub, report)
                    print("Fixture " + name + ": HTTP contract complete", flush=True)
                a, b = fixtures
                report.record("cookie.isolation", lambda: cookie_isolation(a, b), group="A/B isolation")
                # Identical historical Noise client exercises normal node behavior on A and B.
                for hub in fixtures:
                    node_suite(hub, report, "noise", scripts["noise"], True, differential=True)
                for label, _, encrypted in NODE_REFS:
                    if label != "noise":
                        node_suite(b, report, label, scripts[label], encrypted)
                        print("Historical node " + label + ": compatibility complete", flush=True)
                node_suite(b, report, "candidate", b_source / "node.py", True)
                report.compare()
            finally:
                for hub in reversed(fixtures):
                    try:
                        hub.close()
                    except Exception as exc:
                        report.cases.append({
                            "name": "fixture.cleanup", "group": "isolation", "status": "failed",
                            "detail": report.redact(type(exc).__name__ + ": " + str(exc)),
                        })
    except Exception as exc:
        report.cases.append({
            "name": "harness.setup-or-execution", "group": "harness", "status": "failed",
            "detail": report.redact(type(exc).__name__ + ": " + str(exc)),
        })
    report.metadata["finished_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result = report.write(output)
    print("A/B report: " + str(output / "report.json"), flush=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
