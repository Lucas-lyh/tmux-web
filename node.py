#!/usr/bin/env python3
"""tmux-web child node: offer tmux-like sessions on a machine WITHOUT tmux.

Runs against a tmux-web server (server.py):

    python3 node.py --server ws://HOST:59999/ws-node --name gpu1

Set TMUX_WEB_NODE_TOKEN to the server's node secret (or pass --token-file).
The secret is available through /api/nodes or the web UI's
"nodes" panel. Sessions created here show up on the dashboard as
"<name>:<session>" and support attach, resize, file up/download and
capture, just like local tmux sessions.

Dependencies: Python 3.10+ (Unix/Linux). The standalone node installs its
pinned Noise dependency into a private user cache on first launch if needed.

All application messages use Noise_NNpsk0_25519_ChaChaPoly_SHA256 encryption
and authentication with the existing node secret. No certificate setup is
required, and neither the secret nor session metadata goes in the URL.
TLS (wss://) remains an optional additional outer layer.
Inside encryption, text messages are JSON control messages; binary messages
are [kind:1B][id:8B big-endian][payload].
Note: sessions live as long as THIS agent process lives; if the agent (or
the machine) dies, its sessions are gone.
"""

import argparse
import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import pty
import re
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

PROTO_VERSION = 2

NOISE_PROTOCOL = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
NOISE_PROLOGUE = b"tmux-web/node/v2"
NOISE_PSK_CONTEXT = b"tmux-web/node/v2/psk"
NOISE_DEPENDENCY = "noiseprotocol==0.3.1"
NOISE_MAX_MESSAGE = 8 * 1024 * 1024
NOISE_MAX_RECORD = 65535
NOISE_HEADER = struct.Struct("!BII")  # encrypted kind, total length, offset
NOISE_CHUNK = NOISE_MAX_RECORD - 16 - NOISE_HEADER.size

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


class NoiseError(WsClosed, ConnectionError):
    """Encrypted channel authentication or framing failed; never fall back."""


def _noise_class():
    from noise.connection import NoiseConnection
    return NoiseConnection


def ensure_noise_dependency() -> None:
    """Install only into a private cache, never into the system interpreter."""
    try:
        _noise_class()
        return
    except ImportError:
        pass
    import fcntl
    import importlib
    import venv

    cache_base = os.path.expanduser("~/.cache/tmux-web")
    os.makedirs(cache_base, mode=0o700, exist_ok=True)
    if os.path.islink(cache_base) or os.stat(cache_base).st_uid != os.getuid():
        raise RuntimeError("encrypted transport cache must be a private directory owned by this user")
    os.chmod(cache_base, 0o700)
    cache = os.path.join(cache_base, "noiseprotocol-0.3.1-" + sys.implementation.cache_tag)
    lock_fd = os.open(os.path.join(cache_base, ".noise-install.lock"),
                      os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if os.path.islink(cache):
            raise RuntimeError("encrypted transport cache must not be a symbolic link")

        def load_cache():
            # A failed import can leave the namespace package in sys.modules.
            for name in list(sys.modules):
                if name == "noise" or name.startswith("noise."):
                    sys.modules.pop(name, None)
            if cache not in sys.path:
                sys.path.insert(0, cache)
            importlib.invalidate_caches()
            return _noise_class()

        if os.path.isdir(cache):
            try:
                load_cache()
                return
            except ImportError:
                # Only this versioned private dependency cache is replaced.
                shutil.rmtree(cache)
        print("[node] preparing encrypted transport dependency (first launch) ...", file=sys.stderr)
        with tempfile.TemporaryDirectory(prefix=".noise-install-", dir=cache_base) as work:
            installer = sys.executable
            probe = subprocess.run([installer, "-m", "pip", "--version"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode:
                try:
                    venv_path = os.path.join(work, "installer")
                    venv.EnvBuilder(with_pip=True).create(venv_path)
                    installer = os.path.join(venv_path, "bin", "python")
                except Exception:
                    raise RuntimeError("automatic encrypted transport setup requires Python pip or venv/ensurepip") from None
            target = os.path.join(work, "packages")
            # pip may include credential-bearing index URLs in diagnostics;
            # suppress subprocess output and report only a fixed failure.
            result = subprocess.run([
                installer, "-m", "pip", "install", "--disable-pip-version-check",
                "--no-input", "--quiet", "--target", target, NOISE_DEPENDENCY,
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode:
                raise RuntimeError("automatic encrypted transport dependency download failed; check package network access")
            os.replace(target, cache)
        try:
            load_cache()
        except ImportError:
            raise RuntimeError("encrypted transport dependency could not be loaded") from None


class NoiseChannel:
    """Authenticated application records over a binary-capable raw transport.

    Each encrypted record contains a kind, total message length and offset.
    All records for one application message are sent under one lock. Noise's
    directional cipher nonces reject tampering, reordering and replay.
    """

    def __init__(self, raw, noise):
        self.raw = raw
        self.noise = noise
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._closed = False

    @classmethod
    async def establish(cls, raw, token: str, initiator: bool):
        channel = cls(raw, None)
        try:
            validate_node_token(token)
            channel.noise = noise = _noise_class().from_name(NOISE_PROTOCOL)
            noise.set_prologue(NOISE_PROLOGUE)
            noise.set_psks(psk=hmac.new(token.encode("utf-8"),
                                      NOISE_PSK_CONTEXT, hashlib.sha256).digest())
            if initiator:
                noise.set_as_initiator()
            else:
                noise.set_as_responder()
            noise.start_handshake()

            async def handshake():
                if initiator:
                    await raw.send(bytes(noise.write_message()))
                incoming = await raw.recv()
                # This fixed pattern with empty payloads has two 48-byte
                # handshake messages. No unauthenticated application data.
                if not isinstance(incoming, bytes) or len(incoming) != 48:
                    raise NoiseError("invalid encrypted handshake")
                if noise.read_message(incoming):
                    raise NoiseError("unexpected encrypted handshake payload")
                if not initiator:
                    await raw.send(bytes(noise.write_message()))
                if not noise.handshake_finished:
                    raise NoiseError("incomplete encrypted handshake")

            await asyncio.wait_for(handshake(), 15)
            return channel
        except asyncio.CancelledError:
            await channel.close(1008, "encrypted channel closed")
            raise
        except Exception:
            await channel.close(1008, "encrypted channel rejected")
            raise NoiseError("encrypted handshake authentication failed") from None

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            # Close status is transport metadata: never send application
            # errors or caller-provided text outside encryption.
            await asyncio.wait_for(self.raw.close(code=code, reason=""), 3)

    async def send(self, message: str | bytes) -> None:
        if self._closed:
            raise NoiseError("encrypted channel is closed")
        if isinstance(message, str):
            kind, payload = 1, message.encode("utf-8")
        elif isinstance(message, bytes):
            kind, payload = 2, message
        else:
            raise TypeError("encrypted channel messages must be text or bytes")
        if len(payload) > NOISE_MAX_MESSAGE:
            await self.close(1009)
            raise NoiseError("encrypted application message exceeds size limit")
        async with self._send_lock:
            try:
                if self._closed:
                    raise NoiseError("encrypted channel is closed")
                for offset in range(0, max(1, len(payload)), NOISE_CHUNK):
                    clear = NOISE_HEADER.pack(kind, len(payload), offset) + payload[offset:offset + NOISE_CHUNK]
                    await self.raw.send(bytes(self.noise.encrypt(clear)))
            except asyncio.CancelledError:
                await self.close(1008)
                raise
            except Exception:
                await self.close(1008)
                raise NoiseError("encrypted channel send failed") from None

    async def recv(self) -> str | bytes:
        async with self._recv_lock:
            try:
                if self._closed:
                    raise NoiseError("encrypted channel is closed")
                payload = bytearray()
                expected = None
                while True:
                    incoming = await self.raw.recv()
                    if not isinstance(incoming, bytes) or not 25 <= len(incoming) <= NOISE_MAX_RECORD:
                        raise NoiseError("invalid encrypted record")
                    clear = self.noise.decrypt(incoming)
                    if len(clear) < NOISE_HEADER.size:
                        raise NoiseError("invalid encrypted record header")
                    kind, total, offset = NOISE_HEADER.unpack_from(clear)
                    chunk = clear[NOISE_HEADER.size:]
                    if (kind not in (1, 2) or total > NOISE_MAX_MESSAGE
                            or offset != len(payload) or offset + len(chunk) > total
                            or (not chunk and total != 0)
                            or expected is not None and expected != (kind, total)):
                        raise NoiseError("invalid encrypted message framing")
                    expected = kind, total
                    payload.extend(chunk)
                    if len(payload) == total:
                        return payload.decode("utf-8") if kind == 1 else bytes(payload)
            except asyncio.CancelledError:
                # A cancelled read may have consumed part of a message. The
                # connection must not continue with lost reassembly state.
                await self.close(1008)
                raise
            except Exception:
                await self.close(1008)
                raise NoiseError("encrypted channel authentication or framing failed") from None

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._closed:
            raise StopAsyncIteration
        return await self.recv()


def validate_server_url(url: str, *, allow_insecure_ws: bool = False):
    """Validate before urlsplit can discard characters or build HTTP headers."""
    if (not isinstance(url, str) or not url or not url.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in url)
            or "\\" in url or "#" in url
            or re.search(r"%(?![0-9a-fA-F]{2})", url)):
        raise ValueError("server URL must be an ASCII URL without whitespace or a fragment")
    try:
        u = urllib.parse.urlsplit(url)
        hostname, port = u.hostname, u.port
    except ValueError:
        raise ValueError("invalid server URL or port") from None
    if u.scheme not in ("ws", "wss") or not hostname:
        raise ValueError("server URL must use wss:// with a hostname")
    if u.scheme == "ws" and not allow_insecure_ws:
        raise ValueError("unencrypted ws:// is disabled; use wss:// (or explicitly --allow-insecure-ws)")
    if u.username is not None or u.password is not None:
        raise ValueError("server URL must not contain credentials")
    if (not re.fullmatch(r"[A-Za-z0-9._:-]+", hostname)
            or port == 0 or u.netloc.endswith(":")):
        raise ValueError("invalid server hostname or port")
    if any(ord(c) < 32 or ord(c) == 127 for c in urllib.parse.unquote(url)):
        raise ValueError("server URL must not contain encoded control characters")
    if any(key.lower() == "token" for key, _ in
           urllib.parse.parse_qsl(u.query, keep_blank_values=True)):
        raise ValueError("server URL must not contain a token; use --token-file or TMUX_WEB_NODE_TOKEN")
    return u


def validate_node_token(token: str) -> None:
    # Keep existing generated token formats valid, without control characters.
    if (not isinstance(token, str) or not token
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token)):
        raise ValueError("node token must be a non-empty ASCII token without whitespace")


def node_ssl_context(ca_file: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


async def _close_writer(writer) -> None:
    writer.close()
    with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 3)


class Ws:
    """Minimal RFC6455 client with verified TLS, masking and no extensions."""

    def __init__(self, reader, writer):
        self.r = reader
        self.w = writer
        self._wlock = asyncio.Lock()
        self._frag = None
        self.max_message_size = NOISE_MAX_MESSAGE
        self.last_seen = time.time()

    @classmethod
    async def connect(cls, url: str, *, token: str | None = None,
                      ssl_context: ssl.SSLContext | None = None,
                      allow_insecure_ws: bool = False) -> "Ws":
        u = validate_server_url(url, allow_insecure_ws=allow_insecure_ws)
        if token is not None:
            validate_node_token(token)
        tls = u.scheme == "wss"
        port = u.port or (443 if tls else 80)
        options = {}
        if tls:
            ctx = ssl_context if ssl_context is not None else node_ssl_context()
            if (not ctx.check_hostname or ctx.verify_mode != ssl.CERT_REQUIRED
                    or ctx.minimum_version < ssl.TLSVersion.TLSv1_2):
                raise ValueError("node TLS requires hostname/certificate verification and TLS 1.2 or newer")
            options = {"ssl": ctx, "server_hostname": u.hostname,
                       "ssl_handshake_timeout": 10}
        writer = None
        try:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(u.hostname, port, **options), 10)
            except asyncio.TimeoutError:
                raise ConnectionError("node TCP/TLS connection timed out") from None
            key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
            if u.port is not None:
                host += f":{port}"
            auth = f"Authorization: Bearer {token}\r\n" if token is not None else ""
            writer.write((
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n{auth}\r\n").encode("ascii"))
            await writer.drain()
            try:
                resp = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            except asyncio.TimeoutError:
                raise ConnectionError("node WebSocket handshake timed out") from None
            lines = resp[:-4].split(b"\r\n")
            if not re.fullmatch(rb"HTTP/1\.1 101(?: [\x20-\x7e]*)?", lines[0]):
                # A proxy can reflect the request (including credentials) in an
                # error response. Never include its status or headers in logs.
                raise ConnectionError("node WebSocket handshake rejected (expected HTTP 101)")
            headers = {}
            for line in lines[1:]:
                name, sep, value = line.partition(b":")
                if (not sep or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                        or any(c < 32 and c != 9 or c == 127 for c in value)):
                    raise ConnectionError("invalid WebSocket handshake headers")
                headers.setdefault(name.lower(), []).append(value.strip())
            expected = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest())
            connection = b",".join(headers.get(b"connection", [])).lower().split(b",")
            if [v.lower() for v in headers.get(b"upgrade", [])] != [b"websocket"]:
                raise ConnectionError("invalid WebSocket Upgrade header")
            if (b"upgrade" not in [v.strip() for v in connection]
                    or headers.get(b"sec-websocket-accept", []) != [expected]
                    or b"sec-websocket-extensions" in headers
                    or b"sec-websocket-protocol" in headers):
                raise ConnectionError("invalid WebSocket handshake validation")
            return cls(reader, writer)
        except BaseException:
            if writer is not None:
                await _close_writer(writer)
            raise

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
            if (hdr[0] & 0x70 or hdr[1] & 0x80 or n > self.max_message_size
                    or op not in (0, 1, 2, 8, 9, 10)
                    or op >= 8 and (not fin or n > 125)):
                raise WsClosed("invalid WebSocket frame")
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
                    raise WsClosed("unexpected WebSocket continuation")
                fop, fbuf = self._frag
                if len(fbuf) + len(data) > self.max_message_size:
                    raise WsClosed("WebSocket message exceeds size limit")
                fbuf += data
                if fin:
                    self._frag = None
                    return fop, bytes(fbuf)
                continue
            if self._frag is not None:
                raise WsClosed("unfinished WebSocket message")
            if not fin:
                self._frag = (op, bytearray(data))
                continue
            return op, data

    async def close(self) -> None:
        try:
            await _close_writer(self.w)
        except Exception:
            pass


class WsRaw:
    """Adapt the minimal WebSocket client to NoiseChannel's transport API."""

    def __init__(self, ws: Ws):
        self.ws = ws
        ws.max_message_size = NOISE_MAX_RECORD

    async def send(self, data: bytes) -> None:
        await self.ws.send_frame(2, data)

    async def recv(self) -> str | bytes:
        opcode, data = await self.ws.recv()
        if opcode == 2:
            return data
        if opcode == 1:
            return data.decode("utf-8")
        raise NoiseError("encrypted channel requires binary WebSocket messages")

    async def close(self, code: int = 1000, reason: str = "") -> None:
        await self.ws.close()


class NodeConnection:
    """Keep Agent's terminal/file API while encrypting every application message."""

    def __init__(self, ws: Ws, channel: NoiseChannel):
        self.raw_ws = ws
        self.channel = channel

    @property
    def last_seen(self):
        return self.raw_ws.last_seen

    async def send_json(self, obj: dict) -> None:
        await self.channel.send(json.dumps(obj))

    async def send_binary(self, kind: int, rid: int, payload: bytes) -> None:
        await self.channel.send(bytes([kind]) + rid.to_bytes(8, "big") + payload)

    async def recv(self):
        message = await self.channel.recv()
        return (1, message.encode("utf-8")) if isinstance(message, str) else (2, message)

    async def send_frame(self, opcode: int, data: bytes) -> None:
        if opcode not in (9, 10) or data:
            raise ValueError("only empty WebSocket transport probes may bypass encryption")
        await self.raw_ws.send_frame(opcode, data)

    async def close(self) -> None:
        await self.channel.close()


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
                # Output is also in the replay buffer. Keep this sender alive
                # so the hub can re-watch and receive output after reconnect.
                continue

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
                 portal_url: str = "", portal_insecure: bool = False, *,
                 ssl_context: ssl.SSLContext | None = None,
                 allow_insecure_ws: bool = True):
        endpoint = validate_server_url(server, allow_insecure_ws=True)
        validate_node_token(token)
        self.server = server
        self.node_url = urllib.parse.urlunsplit(
            endpoint._replace(query="v=2"))
        self.token = token
        self.name = name
        self.ssl_context = ssl_context
        self.allow_insecure_ws = True  # The outer WebSocket always carries Noise.
        self._hello_received = False
        self.portal_user = portal_user
        self.portal_pass = portal_pass
        self.portal_url = portal_url
        self.portal_insecure = portal_insecure
        self._last_portal_try = 0.0
        self.sessions: dict[int, Session] = {}
        self.next_sid = 0
        self.ws: NodeConnection | None = None
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
            self._hello_received = False
            try:
                print(f"[node] connecting to {urllib.parse.urlsplit(self.server).hostname} as {self.name!r} ...")
                raw_ws = await asyncio.wait_for(Ws.connect(
                    self.node_url, ssl_context=self.ssl_context,
                    allow_insecure_ws=True), 25)
                channel = await NoiseChannel.establish(WsRaw(raw_ws), self.token, initiator=True)
                self.ws = NodeConnection(raw_ws, channel)
                await self.serve()
            except ssl.SSLCertVerificationError:
                print("[node] TLS certificate verification failed; check the server hostname, certificate chain or --ca-file")
                await self.maybe_portal_login()
            except ssl.SSLError:
                print("[node] TLS handshake/connection failed; check the server TLS configuration")
                await self.maybe_portal_login()
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
                if self._hello_received:
                    backoff = 1
            print(f"[node] retrying in {backoff}s")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def serve(self) -> None:
        await self.send_json({
            "type": "hello", "version": PROTO_VERSION, "name": self.name,
            "sessions": [{"sid": s.sid, "name": s.name, "cols": s.cols, "rows": s.rows}
                         for s in self.sessions.values()],
        })
        recv_task = None
        try:
            while True:
                if recv_task is None:
                    recv_task = asyncio.create_task(self.ws.recv())
                try:
                    # Keep the same read alive across idle probes: cancelling
                    # recv() after half a frame would lose its framing state.
                    op, data = await asyncio.wait_for(asyncio.shield(recv_task), 60)
                except asyncio.TimeoutError:
                    # The hub pings us every ~20s; 2 minutes of total silence
                    # means the link is silently dead and needs reconnecting.
                    if time.time() - self.ws.last_seen > 120:
                        raise WsClosed("keepalive timeout")
                    await self.ws.send_frame(0x9, b"")
                    continue
                recv_task = None
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
        finally:
            if recv_task is not None:
                recv_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await recv_task

    # -- control messages ---------------------------------------------------
    async def handle(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "hello-ok":
            if not self._hello_received:
                print(f"[node] connected; {len(self.sessions)} session(s) registered")
            self._hello_received = True
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
                    help="node endpoint, e.g. ws://host:59999/ws-node (always Noise encrypted)")
    ap.add_argument("--ca-file", default=os.environ.get("TMUX_WEB_CA_FILE") or None,
                    help="PEM CA bundle for server verification (or TMUX_WEB_CA_FILE)")
    ap.add_argument("--allow-insecure-ws", action="store_true",
                    help=argparse.SUPPRESS)  # Accepted for old commands; Noise is mandatory.
    credentials = ap.add_mutually_exclusive_group()
    credentials.add_argument("--token", help="the server's node secret")
    credentials.add_argument("--token-file", help="read the node secret from this file")
    default_name = re.sub(r"[^A-Za-z0-9_.-]", "-", socket.gethostname())[:32] or "node"
    ap.add_argument("--name", default=default_name,
                    help="this node's display name (default: local hostname)")
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
    try:
        endpoint = validate_server_url(args.server, allow_insecure_ws=True)
        validate_node_token(args.token)
    except ValueError as e:
        ap.error(str(e))
    tls_context = None
    if endpoint.scheme == "wss":
        try:
            tls_context = node_ssl_context(
                os.path.expanduser(args.ca_file) if args.ca_file else None)
        except (OSError, ValueError) as e:
            ap.error(f"cannot load TLS trust configuration: {type(e).__name__}")
    portal_config = (args.portal_url, args.portal_user, args.portal_pass)
    if any(portal_config) and not all(portal_config):
        ap.error("portal auto-login requires a URL, username and password")
    if args.portal_url:
        portal = urllib.parse.urlsplit(args.portal_url)
        if portal.scheme not in ("http", "https") or not portal.hostname:
            ap.error("--portal-url must be an http:// or https:// base URL")
        if portal.username or portal.password or portal.query or portal.fragment:
            ap.error("--portal-url must not include credentials, a query or a fragment")
    try:
        ensure_noise_dependency()
    except RuntimeError as e:
        ap.error(str(e))
    except Exception as e:
        ap.error(f"cannot prepare encrypted transport: {type(e).__name__}")
    cleanup_uploads()
    agent = Agent(args.server, args.token, args.name,
                  args.portal_user, args.portal_pass, args.portal_url, args.portal_insecure,
                  ssl_context=tls_context)
    await agent.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
