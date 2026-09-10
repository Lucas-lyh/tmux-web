#!/usr/bin/env python3
"""tmux-web child node: offer tmux-like sessions on a machine WITHOUT tmux.

Runs against a tmux-web server (server.py):

    python3 node.py --server ws://HOST:59999/ws-node --name gpu1

Set TMUX_WEB_NODE_TOKEN to the server's node secret (or pass --token-file).
The secret is available through /api/nodes or the web UI's
"nodes" panel. Sessions created here show up on the dashboard as
"<name>:<session>" and support attach, resize, file up/download and
capture, just like local tmux sessions.

Dependencies: Python 3.10+ standard library only (Unix/Linux).

Protocol over a single websocket: text frames are JSON control messages;
binary frames are [kind:1B][id:8B big-endian][payload].
Note: sessions live as long as THIS agent process lives; if the agent (or
the machine) dies, its sessions are gone.
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import pty
import re
import secrets
import shutil
import signal
import ssl
import struct
import sys
import tempfile
import time
import urllib.parse
import urllib.request

PROTO_VERSION = 1

KIND_OUTPUT = 0     # node -> hub: terminal output (id = session id)
KIND_INPUT = 1      # hub -> node: terminal input (id = session id)
KIND_FILE_DATA = 2  # node -> hub: file-get chunk (id = request id)
KIND_FILE_PUT = 3   # hub -> node: file-put chunk (id = request id)

BUF_CAP = 256 * 1024          # per-session replay buffer
CHUNK = 256 * 1024            # file transfer chunk size
UPLOAD_DIR = "/tmp/tmux-node-uploads"


def set_winsize(fd: int, cols: int, rows: int) -> None:
    import fcntl
    import termios
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


ANSI_RE = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()#][0-9A-B]|[=>MEHc78])")


def strip_ansi(data: bytes) -> str:
    return ANSI_RE.sub("", data.decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# Optional srun campus portal auto-login. Set the portal URL, username and
# password explicitly to enable reconnecting through a captive portal.
# Credentials are read from the environment or command-line options.
# ---------------------------------------------------------------------------
PORTAL_USER = os.environ.get("TMUX_WEB_PORTAL_USER", "")
PORTAL_PASS = os.environ.get("TMUX_WEB_PORTAL_PASS", "")
PORTAL_URL = os.environ.get("TMUX_WEB_PORTAL_URL", "")

_B64_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def _b64(s: str) -> str:
    out = []
    imax = len(s) - len(s) % 3
    for i in range(0, imax, 3):
        b10 = (ord(s[i]) << 16) | (ord(s[i + 1]) << 8) | ord(s[i + 2])
        out += [_B64_ALPHA[b10 >> 18], _B64_ALPHA[(b10 >> 12) & 63],
                _B64_ALPHA[(b10 >> 6) & 63], _B64_ALPHA[b10 & 63]]
    if len(s) - imax == 1:
        b10 = ord(s[imax]) << 16
        out += [_B64_ALPHA[b10 >> 18], _B64_ALPHA[(b10 >> 12) & 63], "=", "="]
    elif len(s) - imax == 2:
        b10 = (ord(s[imax]) << 16) | (ord(s[imax + 1]) << 8)
        out += [_B64_ALPHA[b10 >> 18], _B64_ALPHA[(b10 >> 12) & 63],
                _B64_ALPHA[(b10 >> 6) & 63], "="]
    return "".join(out)


def _ordat(msg, idx):
    return ord(msg[idx]) if len(msg) > idx else 0


def _sencode(msg, key):
    pwd = [_ordat(msg, i) | _ordat(msg, i + 1) << 8 | _ordat(msg, i + 2) << 16
           | _ordat(msg, i + 3) << 24 for i in range(0, len(msg), 4)]
    if key:
        pwd.append(len(msg))
    return pwd


def _lencode(msg, key):
    ll = (len(msg) - 1) << 2
    if key:
        m = msg[len(msg) - 1]
        if m < ll - 3 or m > ll:
            return None
        ll = m
    for i in range(len(msg)):
        msg[i] = (chr(msg[i] & 0xFF) + chr(msg[i] >> 8 & 0xFF)
                  + chr(msg[i] >> 16 & 0xFF) + chr(msg[i] >> 24 & 0xFF))
    return "".join(msg)[0:ll] if key else "".join(msg)


def _xencode(msg, key):
    if msg == "":
        return ""
    pwd = _sencode(msg, True)
    pwdk = _sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    c = 0x86014019 | 0x183639A0
    q = 6 + 52 // (n + 1)
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        for p in range(n):
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(n & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return _lencode(pwd, False)


def _get_jsonp(url: str, params: dict, insecure: bool = False) -> dict:
    params = dict(params)
    params["callback"] = cb = "jQuery112406951885120277062_" + str(int(time.time() * 1000))
    req = urllib.request.Request(
        url + "?" + urllib.parse.urlencode(params),
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) node.py"})
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
        text = r.read().decode("utf-8", "replace")
    return json.loads(text[len(cb) + 1:-1])


def portal_login(username: str, password: str, portal_url: str,
                 insecure: bool = False) -> dict:
    """Authenticate against a configured srun portal. Blocking; run in executor."""
    base = portal_url.rstrip("/")
    res = _get_jsonp(base + "/cgi-bin/get_challenge", {
        "username": username, "ip": "0.0.0.0", "_": int(time.time() * 1000)}, insecure)
    ip, token = res["client_ip"], res["challenge"]
    md5 = hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()
    info = json.dumps({"username": username, "password": password, "ip": ip,
                       "acid": "1", "enc_ver": "srun_bx1"})
    enc = "{SRBX1}" + _b64(_xencode(info, token))
    chkstr = (token + username + token + md5 + token + "1" + token + ip
              + token + "200" + token + "1" + token + enc)
    return _get_jsonp(base + "/cgi-bin/srun_portal", {
        "action": "login", "username": username, "password": "{MD5}" + md5,
        "ac_id": 1, "ip": ip, "info": enc, "n": "200", "type": "1",
        "os": "Linux.Hercules", "name": "Linux", "double_stack": "",
        "chksum": hashlib.sha1(chkstr.encode()).hexdigest(),
        "_": int(time.time() * 1000)}, insecure)


def internet_ok() -> bool:
    """Cheap connectivity canary; a captive portal breaks it. Blocking."""
    try:
        req = urllib.request.Request("http://www.gstatic.com/generate_204",
                                     headers={"User-Agent": "node.py"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status == 204
    except Exception:
        return False


class WsClosed(Exception):
    pass


class Ws:
    """Minimal RFC6455 websocket client (client-masked, no extensions)."""

    def __init__(self, reader, writer):
        self.r = reader
        self.w = writer
        self._wlock = asyncio.Lock()
        self._frag = None
        self.last_seen = time.time()

    @classmethod
    async def connect(cls, url: str) -> "Ws":
        u = urllib.parse.urlsplit(url)
        if u.scheme != "ws":
            raise ValueError("only ws:// URLs are supported (no TLS yet)")
        port = u.port or 80
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(u.hostname, port), 10)
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"TCP connect to {u.hostname}:{port} timed out "
                f"(firewall/ISP blocking, or wrong address?)")
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        path = u.path + ("?" + u.query if u.query else "")
        host = u.hostname if u.port is None else f"{u.hostname}:{port}"
        writer.write((
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
        await writer.drain()
        try:
            resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        except asyncio.TimeoutError:
            writer.close()
            raise ConnectionError(
                f"handshake timed out: {u.hostname}:{port} accepted TCP but "
                f"sent no HTTP response (half-dead tunnel/proxy?)")
        status = resp.split(b"\r\n", 1)[0].decode("latin1")
        if " 101" not in status:
            writer.close()
            raise ConnectionError(f"handshake failed: {status}")
        return cls(reader, writer)

    async def send_frame(self, opcode: int, data: bytes) -> None:
        async with self._wlock:
            n = len(data)
            header = bytearray([0x80 | opcode])
            if n < 126:
                header.append(0x80 | n)
            elif n < 65536:
                header += bytes([0x80 | 126]) + n.to_bytes(2, "big")
            else:
                header += bytes([0x80 | 127]) + n.to_bytes(8, "big")
            mask = secrets.token_bytes(4)
            header += mask
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            self.w.write(bytes(header) + masked)
            await self.w.drain()

    async def send_json(self, obj: dict) -> None:
        await self.send_frame(1, json.dumps(obj).encode())

    async def send_binary(self, kind: int, rid: int, payload: bytes) -> None:
        await self.send_frame(2, bytes([kind]) + rid.to_bytes(8, "big") + payload)

    async def recv(self):
        """Returns (opcode, data) for a complete text/binary message."""
        while True:
            hdr = await self.r.readexactly(2)
            self.last_seen = time.time()
            fin, op = hdr[0] & 0x80, hdr[0] & 0x0F
            n = hdr[1] & 0x7F
            if n == 126:
                n = int.from_bytes(await self.r.readexactly(2), "big")
            elif n == 127:
                n = int.from_bytes(await self.r.readexactly(8), "big")
            data = await self.r.readexactly(n)
            if op == 0x9:   # ping
                await self.send_frame(0xA, data)
                continue
            if op == 0xA:   # pong
                continue
            if op == 0x8:   # close
                raise WsClosed()
            if op == 0x0:   # continuation
                if self._frag is None:
                    continue
                fop, fbuf = self._frag
                fbuf += data
                if fin:
                    self._frag = None
                    return fop, bytes(fbuf)
                continue
            if not fin:
                self._frag = (op, bytearray(data))
                continue
            return op, data

    async def close(self) -> None:
        try:
            self.w.close()
        except Exception:
            pass


class Session:
    """One shell in a pty, with a replay buffer and a fan-out queue."""

    def __init__(self, agent: "Agent", sid: int, name: str, cols: int, rows: int):
        self.agent = agent
        self.sid = sid
        self.name = name
        self.cols, self.rows = cols, rows
        self.buf = bytearray()
        self.watchers = 0
        self.outq: asyncio.Queue = asyncio.Queue(maxsize=512)
        self.dead = False
        loop = asyncio.get_running_loop()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # child
            env = dict(os.environ, TERM="xterm-256color")
            shell = os.environ.get("SHELL") or "/bin/bash"
            try:
                os.execvpe(shell, [shell, "-l"], env)
            finally:
                os._exit(127)
        set_winsize(self.fd, cols, rows)
        loop.add_reader(self.fd, self._on_read)
        self.sender = asyncio.create_task(self._send_loop())

    def _on_read(self) -> None:
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            data = b""
        if data:
            self.buf += data
            if len(self.buf) > BUF_CAP:
                del self.buf[:-BUF_CAP]
            if self.watchers:
                try:
                    self.outq.put_nowait(data)
                except asyncio.QueueFull:
                    pass  # slow link: drop rather than block the shell
        else:
            asyncio.get_running_loop().remove_reader(self.fd)
            asyncio.create_task(self._finish(notify=True))

    async def _send_loop(self) -> None:
        while True:
            item = await self.outq.get()
            if item is None:
                return
            try:
                await self.agent.send_binary(KIND_OUTPUT, self.sid, item)
            except Exception:
                return  # link is down; agent will re-watch after reconnect

    async def _reap(self) -> None:
        try:
            os.kill(self.pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, os.waitpid, self.pid, 0), 5)
        except (asyncio.TimeoutError, ChildProcessError):
            try:
                os.kill(self.pid, signal.SIGKILL)
                await loop.run_in_executor(None, os.waitpid, self.pid, 0)
            except (ChildProcessError, ProcessLookupError):
                pass

    async def _finish(self, notify: bool) -> None:
        if self.dead:
            return
        self.dead = True
        loop = asyncio.get_running_loop()
        try:
            loop.remove_reader(self.fd)
        except Exception:
            pass
        try:
            self.outq.put_nowait(None)
        except asyncio.QueueFull:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        await self._reap()
        self.agent.sessions.pop(self.sid, None)
        if notify:
            try:
                await self.agent.send_json({"type": "exit", "sid": self.sid})
            except Exception:
                pass

    async def kill(self) -> None:
        await self._finish(notify=False)

    def resize(self, cols: int, rows: int) -> None:
        self.cols, self.rows = cols, rows
        if not self.dead:
            try:
                set_winsize(self.fd, cols, rows)
            except OSError:
                pass


class Agent:
    def __init__(self, server: str, token: str, name: str,
                 portal_user: str = "", portal_pass: str = "",
                 portal_url: str = "", portal_insecure: bool = False):
        self.server = server
        self.token = token
        self.name = name
        self.portal_user = portal_user
        self.portal_pass = portal_pass
        self.portal_url = portal_url
        self.portal_insecure = portal_insecure
        self._last_portal_try = 0.0
        self.sessions: dict[int, Session] = {}
        self.next_sid = 0
        self.ws: Ws | None = None
        self.puts: dict[int, dict] = {}  # file-put transfers in flight

    async def maybe_portal_login(self) -> None:
        """The server link is down; if a campus captive portal is the cause,
        authenticate through it (throttled)."""
        if not (self.portal_url and self.portal_user and self.portal_pass):
            return
        now = time.time()
        if now - self._last_portal_try < 180:
            return
        self._last_portal_try = now
        loop = asyncio.get_running_loop()
        try:
            if await loop.run_in_executor(None, internet_ok):
                return  # internet is fine; the failure is elsewhere
            print("[node] internet unreachable; trying campus portal login ...")
            res = await loop.run_in_executor(
                None, portal_login, self.portal_user, self.portal_pass,
                self.portal_url, self.portal_insecure)
            print("[node] portal login:", "ok" if res.get("error") == "ok" else "rejected")
        except Exception as e:
            print(f"[node] portal login failed: {type(e).__name__}")

    # -- link plumbing ------------------------------------------------------
    async def send_json(self, obj: dict) -> None:
        if self.ws:
            await self.ws.send_json(obj)

    async def send_binary(self, kind: int, rid: int, payload: bytes) -> None:
        if self.ws:
            await self.ws.send_binary(kind, rid, payload)

    async def run(self) -> None:
        backoff = 1
        while True:
            try:
                sep = "&" if "?" in self.server else "?"
                url = (f"{self.server}{sep}name={urllib.parse.quote(self.name)}"
                       f"&token={urllib.parse.quote(self.token)}")
                print(f"[node] connecting to {urllib.parse.urlsplit(self.server).hostname} as {self.name!r} ...")
                self.ws = await asyncio.wait_for(Ws.connect(url), 25)
                await self.serve()
                backoff = 1
            except (WsClosed, ConnectionError, OSError, asyncio.TimeoutError,
                    asyncio.IncompleteReadError) as e:
                print(f"[node] link down: {type(e).__name__}")
                await self.maybe_portal_login()
            except Exception as e:
                print(f"[node] error: {type(e).__name__}")
            finally:
                if self.ws:
                    await self.ws.close()
                self.ws = None
                # sessions keep running locally; the hub will re-watch after
                # we reconnect and re-hello with the session list.
                for s in self.sessions.values():
                    s.watchers = 0
            print(f"[node] retrying in {backoff}s")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def serve(self) -> None:
        await self.send_json({
            "type": "hello", "version": PROTO_VERSION,
            "sessions": [{"sid": s.sid, "name": s.name, "cols": s.cols, "rows": s.rows}
                         for s in self.sessions.values()],
        })
        print(f"[node] connected; {len(self.sessions)} session(s) registered")
        while True:
            try:
                op, data = await asyncio.wait_for(self.ws.recv(), 60)
            except asyncio.TimeoutError:
                # Idle probe: the hub pings us every ~20s, so 2 minutes of
                # total silence means the link is silently dead — reconnect.
                if time.time() - self.ws.last_seen > 120:
                    raise WsClosed("keepalive timeout")
                await self.ws.send_frame(0x9, b"")
                continue
            if op == 1:
                try:
                    msg = json.loads(data)
                except ValueError:
                    continue
                await self.handle(msg)
            elif op == 2 and len(data) >= 9:
                kind, rid = data[0], int.from_bytes(data[1:9], "big")
                payload = bytes(data[9:])
                if kind == KIND_INPUT:
                    s = self.sessions.get(rid)
                    if s and not s.dead:
                        try:
                            os.write(s.fd, payload)
                        except OSError:
                            pass
                elif kind == KIND_FILE_PUT:
                    await self._put_chunk(rid, payload)

    # -- control messages ---------------------------------------------------
    async def handle(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "hello-ok":
            return
        if t == "new":
            await self._new(msg)
        elif t == "kill":
            await self._kill(msg)
        elif t == "resize":
            s = self.sessions.get(msg.get("sid"))
            if s:
                s.resize(int(msg.get("cols", 220)), int(msg.get("rows", 50)))
        elif t == "watch":
            s = self.sessions.get(msg.get("sid"))
            if s and not s.dead:
                s.watchers += 1
                s.resize(int(msg.get("cols", s.cols)), int(msg.get("rows", s.rows)))
                if s.buf:
                    await s.outq.put(bytes(s.buf))  # replay the screen
        elif t == "unwatch":
            s = self.sessions.get(msg.get("sid"))
            if s:
                s.watchers = max(0, s.watchers - 1)
        elif t == "capture":
            await self._capture(msg)
        elif t == "resolve":
            await self._resolve(msg)
        elif t == "file-get":
            asyncio.create_task(self._file_get(msg))
        elif t == "file-put":
            self._put_start(msg)
        elif t == "file-put-done":
            await self._put_done(msg)

    async def _new(self, msg: dict) -> None:
        rid = msg.get("id")
        name = str(msg.get("name", ""))[:64]
        if any(s.name == name for s in self.sessions.values()):
            await self.send_json({"type": "ack", "id": rid, "ok": False,
                                  "error": "session exists"})
            return
        self.next_sid += 1
        sid = self.next_sid
        try:
            s = Session(self, sid, name,
                        int(msg.get("cols", 220)), int(msg.get("rows", 50)))
        except Exception as e:
            await self.send_json({"type": "ack", "id": rid, "ok": False, "error": str(e)})
            return
        self.sessions[sid] = s
        print(f"[node] new session {name!r} (sid {sid})")
        await self.send_json({"type": "ack", "id": rid, "ok": True, "sid": sid})

    async def _kill(self, msg: dict) -> None:
        rid = msg.get("id")
        s = self.sessions.get(msg.get("sid"))
        if not s:
            await self.send_json({"type": "ack", "id": rid, "ok": False,
                                  "error": "no such session"})
            return
        await self.send_json({"type": "ack", "id": rid, "ok": True})
        print(f"[node] kill session {s.name!r} (sid {s.sid})")
        await s.kill()

    async def _capture(self, msg: dict) -> None:
        rid = msg.get("id")
        s = self.sessions.get(msg.get("sid"))
        if not s:
            await self.send_json({"type": "reply", "id": rid, "ok": False,
                                  "error": "no such session"})
            return
        lines = max(1, min(int(msg.get("lines", 50)), 2000))
        text = strip_ansi(bytes(s.buf)).replace("\r\n", "\n").replace("\r", "\n")
        tail = "\n".join(text.split("\n")[-lines:])
        await self.send_json({"type": "reply", "id": rid, "ok": True, "text": tail})

    async def _resolve(self, msg: dict) -> None:
        rid = msg.get("id")
        p = str(msg.get("path", ""))
        if p.startswith("~"):
            p = os.path.expanduser(p)
        found = None
        if p.startswith("/"):
            q = p
            for _ in range(2048):
                if len(q) < 3:
                    break
                if os.path.isfile(os.path.realpath(q)):
                    found = q
                    break
                q = q[:-1]
        if found is None:
            await self.send_json({"type": "reply", "id": rid, "ok": False})
        else:
            await self.send_json({"type": "reply", "id": rid, "ok": True, "path": found,
                                  "name": os.path.basename(os.path.realpath(found))})

    # -- file transfer ------------------------------------------------------
    async def _file_get(self, msg: dict) -> None:
        rid = msg.get("id")
        p = str(msg.get("path", ""))
        if p.startswith("~"):
            p = os.path.expanduser(p)
        rp = os.path.realpath(p)
        try:
            if not p.startswith("/") or not os.path.isfile(rp):
                raise FileNotFoundError("not a file")
            size = os.path.getsize(rp)
            await self.send_json({"type": "file-meta", "id": rid, "ok": True,
                                  "size": size, "name": os.path.basename(rp)})
            with open(rp, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    await self.send_binary(KIND_FILE_DATA, rid, chunk)
            await self.send_json({"type": "file-end", "id": rid})
        except Exception as e:
            await self.send_json({"type": "file-meta", "id": rid, "ok": False,
                                  "error": str(e)})

    def _put_start(self, msg: dict) -> None:
        rid = msg.get("id")
        name = os.path.basename(str(msg.get("name", ""))).strip()[:128] or "file"
        try:
            size = int(msg.get("size", -1))
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            updir = tempfile.mkdtemp(prefix="up-", dir=UPLOAD_DIR)
            os.chmod(updir, 0o700)
            path = os.path.join(updir, name)
            self.puts[rid] = {"f": open(path, "wb"), "path": path,
                              "size": size, "received": 0}
        except Exception as e:
            self.puts.pop(rid, None)
            asyncio.create_task(self.send_json(
                {"type": "ack", "id": rid, "ok": False, "error": str(e)}))

    async def _put_chunk(self, rid: int, payload: bytes) -> None:
        st = self.puts.get(rid)
        if not st:
            return
        st["f"].write(payload)
        st["received"] += len(payload)

    async def _put_done(self, msg: dict) -> None:
        rid = msg.get("id")
        st = self.puts.pop(rid, None)
        if not st:
            await self.send_json({"type": "ack", "id": rid, "ok": False,
                                  "error": "no such transfer"})
            return
        st["f"].close()
        if st["received"] != st["size"]:
            shutil.rmtree(os.path.dirname(st["path"]), ignore_errors=True)
            await self.send_json({"type": "ack", "id": rid, "ok": False,
                                  "error": "size mismatch"})
            return
        os.chmod(st["path"], 0o600)
        await self.send_json({"type": "ack", "id": rid, "ok": True, "path": st["path"]})


def cleanup_uploads() -> None:
    try:
        now = time.time()
        for d in os.listdir(UPLOAD_DIR):
            p = os.path.join(UPLOAD_DIR, d)
            try:
                if now - os.path.getmtime(p) > 86400:
                    shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass
    except OSError:
        pass


async def main() -> None:
    ap = argparse.ArgumentParser(description="tmux-web child node (no tmux required)")
    ap.add_argument("--server", required=True,
                    help="node endpoint, e.g. ws://host:59999/ws-node")
    credentials = ap.add_mutually_exclusive_group()
    credentials.add_argument("--token", help="the server's node secret")
    credentials.add_argument("--token-file", help="read the node secret from this file")
    ap.add_argument("--name", required=True, help="this node's display name")
    ap.add_argument("--portal-url", default=PORTAL_URL,
                    help="srun portal base URL (or TMUX_WEB_PORTAL_URL; disabled by default)")
    ap.add_argument("--portal-user", default=PORTAL_USER,
                    help="campus portal username (or TMUX_WEB_PORTAL_USER)")
    ap.add_argument("--portal-pass", default=PORTAL_PASS,
                    help="campus portal password (or TMUX_WEB_PORTAL_PASS)")
    ap.add_argument("--portal-insecure", action="store_true",
                    help="disable TLS certificate verification for the configured portal")
    args = ap.parse_args()
    if args.token_file:
        try:
            with open(os.path.expanduser(args.token_file), encoding="utf-8") as f:
                args.token = f.read().strip()
        except (OSError, UnicodeError) as e:
            ap.error(f"cannot read --token-file: {type(e).__name__}")
    else:
        args.token = args.token or os.environ.get("TMUX_WEB_NODE_TOKEN", "")
    if not args.token:
        ap.error("provide --token-file, --token or set TMUX_WEB_NODE_TOKEN")
    portal_config = (args.portal_url, args.portal_user, args.portal_pass)
    if any(portal_config) and not all(portal_config):
        ap.error("portal auto-login requires a URL, username and password")
    if args.portal_url:
        portal = urllib.parse.urlsplit(args.portal_url)
        if portal.scheme not in ("http", "https") or not portal.hostname:
            ap.error("--portal-url must be an http:// or https:// base URL")
        if portal.username or portal.password or portal.query or portal.fragment:
            ap.error("--portal-url must not include credentials, a query or a fragment")
    cleanup_uploads()
    agent = Agent(args.server.rstrip("/"), args.token, args.name,
                  args.portal_user, args.portal_pass, args.portal_url, args.portal_insecure)
    await agent.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
