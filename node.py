#!/usr/bin/env python3
"""tmux-web child node: offer tmux-like sessions on a machine WITHOUT tmux.

Runs against a tmux-web server (server.py):

    python3 node.py --server ws://HOST:59999/ws-node --name gpu1

Set TMUX_WEB_NODE_TOKEN to the server's node secret (or pass --token-file).
The secret is available through /api/nodes or the web UI's
"nodes" panel. Sessions created here show up on the dashboard as
"<name>:<session>" and support attach, resize, file up/download and
capture, just like local tmux sessions.

Dependencies: Python 3.8+ standard library only (Unix/Linux).

All application messages use Noise_NNpsk0_25519_ChaChaPoly_SHA256 encryption
and authentication with the existing node secret. No certificate setup is
required, and neither the secret nor session metadata goes in the URL.
The cipher and handshake are built into this file; no package installation.
Inside encryption, text messages are JSON control messages; binary messages
are [kind:1B][id:8B big-endian][payload].
Note: sessions live as long as THIS agent process lives; if the agent (or
the machine) dies, its sessions are gone.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
from collections import deque
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
import stat
import struct
import sys
import tempfile
import time
import urllib.parse
import urllib.request

PROTO_VERSION = 2

NOISE_PROTOCOL = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
NOISE_PROLOGUE = b"tmux-web/node/v2"
NOISE_PSK_CONTEXT = b"tmux-web/node/v2/psk"
NOISE_MAX_MESSAGE = 8 * 1024 * 1024
NOISE_MAX_RECORD = 65535
NOISE_HEADER = struct.Struct("!BII")  # encrypted kind, total length, offset
NOISE_CHUNK = NOISE_MAX_RECORD - 16 - NOISE_HEADER.size

KIND_OUTPUT = 0     # node -> hub: terminal output (id = session id)
KIND_INPUT = 1      # hub -> node: terminal input (id = session id)
KIND_FILE_DATA = 2  # node -> hub: file-get chunk (id = request id)
KIND_FILE_PUT = 3   # hub -> node: file-put chunk (id = request id)

BUF_CAP = 256 * 1024          # per-session replay buffer
CHUNK = 16 * 1024             # bound each file message's encryption/send lock
UPLOAD_DIR = "/tmp/tmux-node-uploads"
MAX_UPLOADS = 32
UPLOAD_IDLE_TIMEOUT = 15 * 60


async def _file_io(operation, *args, cancel_cleanup=None):
    """Keep blocking file I/O off the loop without closing a live worker's fd.

    Cancellation waits for the one outstanding operation before unwinding its
    owner's finally block. Resource-producing calls can dispose their result
    if cancellation prevented ownership from reaching the caller.
    """
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(None, operation, *args)
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        while not future.done():
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        try:
            result = future.result()
        except Exception:
            pass
        else:
            if cancel_cleanup is not None:
                cleanup = loop.run_in_executor(None, cancel_cleanup, result)
                while not cleanup.done():
                    try:
                        await asyncio.shield(cleanup)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                with contextlib.suppress(Exception):
                    cleanup.result()
        raise


class CredentialError(ValueError):
    """A fixed, credential-free cache or handoff diagnostic."""


def node_credential_parts(token: str):
    if not isinstance(token, str):
        return None
    match = re.fullmatch(r"(twj|twn)\.([0-9a-f]{32})\.([0-9a-f]{64})", token)
    return match.groups() if match else None


def node_credential_directory() -> str:
    return os.path.expanduser("~/.local/state/tmux-web/node-credentials")


def _credential_filename(server: str, name: str, credential_id: str) -> str:
    endpoint = urllib.parse.urlsplit(server)
    scope = [endpoint.scheme, endpoint.hostname.lower(), endpoint.port or 80,
             endpoint.path or "/", name]
    digest = hashlib.sha256(json.dumps(scope, separators=(",", ":")).encode()).hexdigest()
    return digest + "." + credential_id + ".token"


def _credential_directory_fd(create: bool):
    directory = node_credential_directory()
    try:
        if create:
            ensure_private_upload_root(directory)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if not create:
            return None
        raise CredentialError("cannot create private node credential directory") from None
    except (OSError, ValueError):
        raise CredentialError("node credential directory must be private and owned by this user") from None
    try:
        info = os.fstat(fd)
        valid = info.st_uid == os.getuid() and info.st_mode & 0o777 == 0o700
    except OSError:
        valid = False
    if not valid:
        os.close(fd)
        raise CredentialError("node credential directory must have private permissions")
    return fd


def _read_cached_credential(directory_fd: int, filename: str, credential_id: str):
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError:
        raise CredentialError("cannot safely read cached node credential") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o777 != 0o600 or not 0 < info.st_size <= 256):
            raise CredentialError("cached node credential must be an owned private regular file")
        try:
            token = os.read(fd, 257).decode("ascii").strip()
        except (OSError, UnicodeError):
            raise CredentialError("cached node credential is invalid") from None
        parts = node_credential_parts(token)
        if parts is None or parts[0] != "twn" or parts[1] != credential_id:
            raise CredentialError("cached node credential does not match this enrollment")
        return token
    finally:
        os.close(fd)


def load_node_credential(server: str, name: str, token: str) -> str:
    parts = node_credential_parts(token)
    if parts is None or parts[0] != "twj":
        return token  # Legacy/manual credentials never create or consult state.
    directory_fd = _credential_directory_fd(False)
    if directory_fd is None:
        return token
    try:
        return _read_cached_credential(directory_fd, _credential_filename(server, name, parts[1]), parts[1]) or token
    finally:
        os.close(directory_fd)


def save_node_credential(server: str, name: str, token: str) -> None:
    parts = node_credential_parts(token)
    if parts is None or parts[0] != "twn":
        raise CredentialError("only a permanent node credential can be cached")
    filename = _credential_filename(server, name, parts[1])
    directory_fd = _credential_directory_fd(True)
    temporary = ".credential-" + secrets.token_hex(12) + ".tmp"
    fd = None
    try:
        _read_cached_credential(directory_fd, filename, parts[1])
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write((token + "\n").encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except (OSError, ValueError):
        raise CredentialError("cannot persist private node credential") from None
    finally:
        if fd is not None:
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(temporary, dir_fd=directory_fd)
        os.close(directory_fd)


def ensure_private_upload_root(path: str) -> str:
    """Open only an owned directory, never a pre-created root symlink."""
    path = os.path.abspath(path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    before = os.lstat(path)
    if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid():
        raise ValueError("upload root must be a directory owned by the current user")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_uid != os.getuid()):
            raise ValueError("upload root changed during validation")
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return path


def cleanup_upload_root(path: str, max_age: float = 86400) -> None:
    """Clean only this user's expired up-* directories below a private root."""
    root = ensure_private_upload_root(path)
    cutoff = time.time() - max_age
    with os.scandir(root) as entries:
        for entry in entries:
            if not re.fullmatch(r"up-[A-Za-z0-9_-]+", entry.name):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
                if (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                        and info.st_mtime < cutoff):
                    shutil.rmtree(entry.path)
            except FileNotFoundError:
                pass


class UploadTransfer:
    """One bounded upload; abort is idempotent and never removes a finished file."""

    def __init__(self, root: str, name: str, size: int):
        if not isinstance(size, int) or size < 0:
            raise ValueError("upload size must be non-negative")
        name = os.path.basename(str(name)).strip()[:128] or "file"
        if name in (".", "..") or "\0" in name:
            raise ValueError("invalid upload filename")
        self.size, self.received = size, 0
        self.updated_at = time.monotonic()
        self.file = None
        self._finished = False
        self.directory = tempfile.mkdtemp(prefix="up-", dir=ensure_private_upload_root(root))
        self.path = os.path.join(self.directory, name)
        fd = None
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self.file = os.fdopen(fd, "wb")
            fd = None
        except BaseException:
            if fd is not None:
                os.close(fd)
            self.abort()
            raise

    def write(self, data: bytes) -> None:
        if self.file is None or self.file.closed:
            raise ValueError("upload is closed")
        try:
            if self.received + len(data) > self.size:
                raise ValueError("upload exceeds declared size")
            if self.file.write(data) != len(data):
                raise OSError("short upload write")
            self.received += len(data)
            self.updated_at = time.monotonic()
        except BaseException:
            self.abort()
            raise

    def finish(self) -> str:
        try:
            if self.file is None or self.file.closed:
                raise ValueError("upload is closed")
            if self.received != self.size:
                raise ValueError("size mismatch")
            self.file.close()
            os.chmod(self.path, 0o600)
            self._finished = True
            return self.path
        except BaseException:
            self.abort()
            raise

    def abort(self) -> None:
        if self._finished:
            return
        if self.file is not None:
            with contextlib.suppress(OSError):
                self.file.close()
        shutil.rmtree(self.directory, ignore_errors=True)


class PtyWriter:
    """Bounded nonblocking PTY input. False rejects a whole new input chunk.

    The owner retains the file descriptor and must handle EAGAIN when reading
    it. close() stops only this writer; it never closes or kills the terminal.
    """

    def __init__(self, fd: int, *, max_buffer: int = 1024 * 1024):
        if max_buffer < 1:
            raise ValueError("PTY input buffer limit must be positive")
        self.fd, self.max_buffer = fd, max_buffer
        self.loop = asyncio.get_running_loop()
        self._queue = deque()
        self._offset = 0
        self.pending_bytes = 0
        self.error = None
        self._closed = False
        self._registered = False
        os.set_blocking(fd, False)

    def write(self, data: bytes) -> bool:
        if self._closed:
            raise self.error or BrokenPipeError("PTY input writer is closed")
        if len(data) + self.pending_bytes > self.max_buffer:
            return False
        if data:
            self._queue.append(bytes(data))
            self.pending_bytes += len(data)
            self._flush()
        if self.error is not None:
            raise self.error
        return True

    def _flush(self) -> None:
        budget = 65536
        try:
            while self._queue and budget > 0:
                first = self._queue[0]
                try:
                    count = os.write(self.fd, memoryview(first)[self._offset:self._offset + budget])
                except InterruptedError:
                    continue
                except BlockingIOError:
                    break
                if count <= 0:
                    raise BrokenPipeError("PTY input writer made no progress")
                self._offset += count
                self.pending_bytes -= count
                budget -= count
                if self._offset == len(first):
                    self._queue.popleft()
                    self._offset = 0
            if self._queue and not self._registered:
                self.loop.add_writer(self.fd, self._flush)
                self._registered = True
            elif not self._queue and self._registered:
                self.loop.remove_writer(self.fd)
                self._registered = False
        except OSError as exc:
            self.error = exc
            self.close()

    def close(self) -> None:
        self._closed = True
        if self._registered:
            with contextlib.suppress(Exception):
                self.loop.remove_writer(self.fd)
            self._registered = False
        self._queue.clear()
        self._offset = self.pending_bytes = 0


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
    import ssl  # Existing optional HTTPS campus-portal requests only.
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


# Fixed Noise NNpsk0 suite implemented here with standard-library primitives.
# Algorithms: RFC 7748 section 5, RFC 8439 sections 2.3/2.5/2.8, and Noise rev 34.
# Python big-integer arithmetic is not guaranteed constant-time. Keep this
# implementation covered by published vectors and cross-implementation tests.

def _x25519(private: bytes, public: bytes) -> bytes:
    if len(private) != 32 or len(public) != 32:
        raise ValueError("invalid X25519 key length")
    p = 2**255 - 19
    scalar = (int.from_bytes(private, "little") & ((1 << 255) - 8)) | (1 << 254)
    u = (int.from_bytes(public, "little") & ((1 << 255) - 1)) % p
    x2, z2, x3, z3, swap = 1, 0, u, 1, 0
    for bit in range(254, -1, -1):
        current = (scalar >> bit) & 1
        swap ^= current
        mask = -swap
        dx, dz = mask & (x2 ^ x3), mask & (z2 ^ z3)
        x2, x3, z2, z3 = x2 ^ dx, x3 ^ dx, z2 ^ dz, z3 ^ dz
        swap = current
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = u * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p
    mask = -swap
    x2 ^= mask & (x2 ^ x3)
    z2 ^= mask & (z2 ^ z3)
    shared = (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")
    if hmac.compare_digest(shared, bytes(32)):
        raise ValueError("invalid X25519 peer")
    return shared


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12 or not 0 <= counter < 2**32:
        raise ValueError("invalid ChaCha20 parameters")
    initial = list(struct.unpack("<4I", b"expand 32-byte k"))
    initial += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    state = initial.copy()
    def quarter(a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xffffffff
        value = state[d] ^ state[a]
        state[d] = ((value << 16) | (value >> 16)) & 0xffffffff
        state[c] = (state[c] + state[d]) & 0xffffffff
        value = state[b] ^ state[c]
        state[b] = ((value << 12) | (value >> 20)) & 0xffffffff
        state[a] = (state[a] + state[b]) & 0xffffffff
        value = state[d] ^ state[a]
        state[d] = ((value << 8) | (value >> 24)) & 0xffffffff
        state[c] = (state[c] + state[d]) & 0xffffffff
        value = state[b] ^ state[c]
        state[b] = ((value << 7) | (value >> 25)) & 0xffffffff
    for _ in range(10):
        quarter(0, 4, 8, 12); quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14); quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15); quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13); quarter(3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xffffffff for a, b in zip(state, initial)])


def _chacha_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    output = bytearray(len(data))
    for offset in range(0, len(data), 64):
        stream = _chacha_block(key, 1 + offset // 64, nonce)
        chunk = data[offset:offset + 64]
        # Integer XOR avoids one Python operation per byte of payload.
        output[offset:offset + len(chunk)] = (int.from_bytes(chunk, "little") ^
            int.from_bytes(stream[:len(chunk)], "little")).to_bytes(len(chunk), "little")
    return bytes(output)


def _poly1305(key: bytes, message: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("invalid Poly1305 key length")
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    accumulator = 0
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        accumulator = ((accumulator + int.from_bytes(block + b"\x01", "little")) * r) % (2**130 - 5)
    return ((accumulator + s) & (2**128 - 1)).to_bytes(16, "little")


def _aead_tag(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    mac_data = (ad + bytes((-len(ad)) % 16) + ciphertext + bytes((-len(ciphertext)) % 16)
                + struct.pack("<QQ", len(ad), len(ciphertext)))
    return _poly1305(_chacha_block(key, 0, nonce)[:32], mac_data)


class _Cipher:
    def __init__(self, key: bytes):
        self.key, self.nonce = key, 0

    def _nonce_bytes(self):
        if not 0 <= self.nonce < 2**64 - 1:
            raise ValueError("cipher nonce exhausted")
        return bytes(4) + self.nonce.to_bytes(8, "little")

    def encrypt(self, ad: bytes, plaintext: bytes) -> bytes:
        nonce = self._nonce_bytes()
        ciphertext = _chacha_xor(self.key, nonce, plaintext)
        result = ciphertext + _aead_tag(self.key, nonce, ad, ciphertext)
        self.nonce += 1
        return result

    def decrypt(self, ad: bytes, data: bytes) -> bytes:
        nonce = self._nonce_bytes()
        if len(data) < 16 or not hmac.compare_digest(data[-16:], _aead_tag(self.key, nonce, ad, data[:-16])):
            raise ValueError("cipher authentication failed")
        plaintext = _chacha_xor(self.key, nonce, data[:-16])
        self.nonce += 1
        return plaintext


def _hkdf(key: bytes, data: bytes, count: int = 2):
    extracted = hmac.digest(key, data, "sha256")
    result, previous = [], b""
    for index in range(1, count + 1):
        previous = hmac.digest(extracted, previous + bytes([index]), "sha256")
        result.append(previous)
    return result


class _Noise:
    """Only the NNpsk0/25519/ChaChaPoly/SHA256 suite; no negotiation/downgrade."""
    def __init__(self, psk: bytes, initiator: bool, *, ephemeral: bytes | None = None):
        if len(psk) != 32:
            raise ValueError("Noise requires a 32-byte PSK")
        self.initiator = initiator
        self.h = hashlib.sha256(NOISE_PROTOCOL).digest() if len(NOISE_PROTOCOL) > 32 else NOISE_PROTOCOL.ljust(32, b"\0")
        self.ck = self.h
        self._mix_hash(NOISE_PROLOGUE)
        self.ck, hashed, key = _hkdf(self.ck, psk, 3)
        self._mix_hash(hashed)
        self.cipher = _Cipher(key)
        self.private = secrets.token_bytes(32) if ephemeral is None else ephemeral
        self.public = _x25519(self.private, b"\x09" + bytes(31))
        self.remote = None
        self.step = 0
        self.handshake_finished = False
        self.tx = self.rx = None

    def _mix_hash(self, data):
        self.h = hashlib.sha256(self.h + data).digest()

    def _mix_key(self, data):
        self.ck, key = _hkdf(self.ck, data)
        self.cipher = _Cipher(key)

    def _ephemeral(self, public):
        self._mix_hash(public)
        self._mix_key(public)  # Required for every e token in a PSK pattern.

    def _finish(self):
        first, second = _hkdf(self.ck, b"")
        self.tx, self.rx = (_Cipher(first), _Cipher(second)) if self.initiator else (_Cipher(second), _Cipher(first))
        self.handshake_finished = True
        self.private = self.cipher = self.ck = None

    def write_message(self, payload: bytes = b"") -> bytes:
        if self.handshake_finished or self.step != (0 if self.initiator else 1):
            raise ValueError("unexpected Noise handshake write")
        if len(payload) > 65535 - 48:
            raise ValueError("Noise handshake too large")
        self._ephemeral(self.public)
        if self.step == 1:
            self._mix_key(_x25519(self.private, self.remote))
        encrypted = self.cipher.encrypt(self.h, payload)
        self._mix_hash(encrypted)
        self.step += 1
        if self.step == 2:
            self._finish()
        return self.public + encrypted

    def read_message(self, data: bytes) -> bytes:
        if self.handshake_finished or self.step != (1 if self.initiator else 0) or not 48 <= len(data) <= 65535:
            raise ValueError("unexpected Noise handshake read")
        self.remote = data[:32]
        self._ephemeral(self.remote)
        if self.step == 1:
            self._mix_key(_x25519(self.private, self.remote))
        payload = self.cipher.decrypt(self.h, data[32:])
        self._mix_hash(data[32:])
        self.step += 1
        if self.step == 2:
            self._finish()
        return payload

    def encrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished or len(data) > 65519:
            raise ValueError("invalid Noise transport write")
        return self.tx.encrypt(b"", data)

    def decrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished or not 16 <= len(data) <= 65535:
            raise ValueError("invalid Noise transport read")
        return self.rx.decrypt(b"", data)


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
            psk = hmac.digest(token.encode("utf-8"), NOISE_PSK_CONTEXT, "sha256")
            channel.noise = noise = _Noise(psk, initiator)

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
                    await asyncio.sleep(0)  # Keep heartbeats responsive during pure-Python encryption.
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
                    await asyncio.sleep(0)
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


def validate_server_url(url: str):
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
    if u.scheme != "ws" or not hostname:
        raise ValueError("server URL must use ws:// with a hostname; encryption is built in")
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


async def _close_writer(writer) -> None:
    writer.close()
    with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 3)


class Ws:
    """Minimal RFC6455 transport; NodeConnection encrypts all application data."""

    def __init__(self, reader, writer):
        self.r = reader
        self.w = writer
        self._wlock = asyncio.Lock()
        self._frag = None
        self.max_message_size = NOISE_MAX_MESSAGE
        self.last_seen = time.time()

    @classmethod
    async def connect(cls, url: str) -> "Ws":
        u = validate_server_url(url)
        port = u.port or 80
        writer = None
        try:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(u.hostname, port), 10)
            except asyncio.TimeoutError:
                raise ConnectionError("node TCP connection timed out") from None
            key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
            if u.port is not None:
                host += f":{port}"
            writer.write((
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n").encode("ascii"))
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
        if not 1 <= cols <= 65535 or not 1 <= rows <= 65535:
            raise ValueError("terminal dimensions must be between 1 and 65535")
        self.agent = agent
        self.sid = sid
        self.name = name
        self.cols, self.rows = cols, rows
        self.buf = bytearray()
        self.watchers = 0
        self.outq: asyncio.Queue = asyncio.Queue(maxsize=512)
        self.dead = False
        self.input_writer = None
        self.sender = None
        loop = asyncio.get_running_loop()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # child
            env = dict(os.environ, TERM="xterm-256color")
            shell = os.environ.get("SHELL") or "/bin/bash"
            try:
                os.execvpe(shell, [shell, "-l"], env)
            finally:
                os._exit(127)
        try:
            set_winsize(self.fd, cols, rows)
            self.input_writer = PtyWriter(self.fd)
            loop.add_reader(self.fd, self._on_read)
            self.sender = asyncio.create_task(self._send_loop())
        except BaseException:
            with contextlib.suppress(Exception):
                loop.remove_reader(self.fd)
            if self.input_writer is not None:
                self.input_writer.close()
            with contextlib.suppress(OSError):
                os.close(self.fd)
            with contextlib.suppress(ProcessLookupError):
                os.kill(self.pid, signal.SIGKILL)
            asyncio.create_task(self._reap())
            raise

    def _on_read(self) -> None:
        try:
            data = os.read(self.fd, 65536)
        except (BlockingIOError, InterruptedError):
            return
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
        while not getattr(self, "dead", False):
            item = await self.outq.get()
            if item is None or getattr(self, "dead", False):
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
        waiter = loop.run_in_executor(None, os.waitpid, self.pid, 0)
        try:
            await asyncio.wait_for(asyncio.shield(waiter), 5)
        except asyncio.TimeoutError:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            with contextlib.suppress(ChildProcessError):
                await waiter
        except ChildProcessError:
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
        if self.input_writer is not None:
            self.input_writer.close()
        while not self.outq.empty():
            self.outq.get_nowait()
        self.outq.put_nowait(None)
        try:
            os.close(self.fd)
        except OSError:
            pass
        cancelled = False
        if self.sender is not None and self.sender is not asyncio.current_task():
            try:
                # Let an in-flight encrypted message finish before stopping;
                # cancelling it midway would invalidate the shared channel.
                await asyncio.wait_for(asyncio.shield(self.sender), 3)
            except asyncio.TimeoutError:
                self.sender.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self.sender
            except asyncio.CancelledError:
                cancelled = True
                self.sender.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self.sender
        await self._reap()
        self.agent.sessions.pop(self.sid, None)
        if notify:
            try:
                await self.agent.send_json({"type": "exit", "sid": self.sid})
            except Exception:
                pass
        if cancelled:
            raise asyncio.CancelledError

    async def kill(self) -> None:
        await self._finish(notify=False)

    def resize(self, cols: int, rows: int) -> None:
        if not 1 <= cols <= 65535 or not 1 <= rows <= 65535:
            return
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
        validate_server_url(server)
        validate_node_token(token)
        self.server = server
        self.name = name
        self.token = load_node_credential(server, name, token)
        self._refresh_node_url()
        self._hello_received = False
        self.portal_user = portal_user
        self.portal_pass = portal_pass
        self.portal_url = portal_url
        self.portal_insecure = portal_insecure
        self._last_portal_try = 0.0
        self.sessions: dict[int, Session] = {}
        self.next_sid = 0
        self.ws: NodeConnection | None = None
        self.puts: dict[int, UploadTransfer] = {}
        self._file_tasks = {}
        self._download_cancels = {}
        self._last_upload_sweep = 0.0

    def _refresh_node_url(self) -> None:
        endpoint = urllib.parse.urlsplit(self.server)
        parts = node_credential_parts(self.token)
        query = "v=2"
        if parts is not None:
            query += "&" + urllib.parse.urlencode({"key": parts[0] + "." + parts[1]})
        self.node_url = urllib.parse.urlunsplit(endpoint._replace(query=query))

    async def _accept_credential(self, token) -> None:
        current, replacement = node_credential_parts(self.token), node_credential_parts(token)
        if (current is None or replacement is None or replacement[0] != "twn"
                or replacement[1] != current[1]):
            raise CredentialError("node credential update does not match this enrollment")
        connection = self.ws
        if connection is None:
            raise CredentialError("node credential update requires an encrypted connection")
        # No cancellation point between durable save and the in-memory switch.
        # A disconnect during ack can immediately reconnect with the saved key.
        save_node_credential(self.server, self.name, token)
        self.token = token
        self._refresh_node_url()
        await connection.send_json({"type": "credential-ack"})

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
                self.token = load_node_credential(self.server, self.name, self.token)
                self._refresh_node_url()
                print(f"[node] connecting to {urllib.parse.urlsplit(self.server).hostname} as {self.name!r} ...")
                raw_ws = await asyncio.wait_for(Ws.connect(
                    self.node_url), 25)
                channel = await NoiseChannel.establish(WsRaw(raw_ws), self.token, initiator=True)
                self.ws = NodeConnection(raw_ws, channel)
                await self.serve()
            except CredentialError:
                print("[node] credential handoff failed; reconnecting with the current credential")
            except (WsClosed, ConnectionError, OSError, asyncio.TimeoutError,
                    asyncio.IncompleteReadError) as e:
                print(f"[node] link down: {type(e).__name__}")
                await self.maybe_portal_login()
            except Exception as e:
                print(f"[node] error: {type(e).__name__}")
            finally:
                old_connection = self.ws
                self.ws = None
                if old_connection:
                    await old_connection.close()
                await self._reset_transfers()
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
        capabilities = ["file-stat", "file-get-cancel", "file-put-abort", "input-error"]
        if node_credential_parts(self.token) is not None:
            capabilities.append("credential-v1")
        await self.send_json({
            "type": "hello", "version": PROTO_VERSION, "name": self.name,
            "capabilities": capabilities,
            "sessions": [{"sid": s.sid, "name": s.name, "cols": s.cols, "rows": s.rows}
                         for s in self.sessions.values()],
        })
        recv_task = None
        try:
            while True:
                self._expire_uploads()
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
                                accepted = s.input_writer.write(payload)
                                error = "Terminal input buffer is full; try a smaller paste." if not accepted else None
                            except OSError:
                                error = "Terminal input is unavailable."
                            if error and time.monotonic() - getattr(s, "last_input_error", 0) >= 1:
                                s.last_input_error = time.monotonic()
                                await self.send_json({"type": "input-error", "sid": rid, "error": error})
                    elif kind == KIND_FILE_PUT:
                        await self._put_chunk(rid, payload)
        finally:
            if recv_task is not None:
                recv_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await recv_task
            await self._reset_transfers()

    # -- control messages ---------------------------------------------------
    async def handle(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "hello-ok":
            if "credential" in msg:
                await self._accept_credential(msg["credential"])
            else:
                parts = node_credential_parts(self.token)
                if parts is not None and parts[0] == "twj":
                    raise CredentialError("enrollment did not provide a permanent node credential")
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
            await self._start_file_get(msg)
        elif t == "file-stat":
            await self._file_stat(msg)
        elif t == "file-get-cancel":
            cancelled = self._download_cancels.get(msg.get("id"))
            if cancelled is not None:
                cancelled.set()
        elif t == "file-put":
            await self._put_start(msg)
        elif t == "file-put-done":
            await self._put_done(msg)
        elif t == "file-put-abort":
            self._abort_upload(msg.get("id"))

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
    async def _start_file_get(self, msg: dict) -> None:
        rid = msg.get("id")
        previous = self._file_tasks.get(rid)
        if previous is not None:
            self._download_cancels[rid].set()
            try:
                await asyncio.wait_for(asyncio.shield(previous), 3)
            except asyncio.TimeoutError:
                previous.cancel()
                await asyncio.gather(previous, return_exceptions=True)
        cancelled = asyncio.Event()
        task = asyncio.create_task(self._file_get(msg, self.ws, cancelled))
        self._file_tasks[rid] = task
        self._download_cancels[rid] = cancelled

        def finished(done):
            if self._file_tasks.get(rid) is done:
                self._file_tasks.pop(rid, None)
                self._download_cancels.pop(rid, None)
            with contextlib.suppress(asyncio.CancelledError, Exception):
                done.result()
        task.add_done_callback(finished)

    @staticmethod
    def _download_path(msg: dict) -> str:
        path = str(msg.get("path", ""))
        if path.startswith("~"):
            path = os.path.expanduser(path)
        if not os.path.isabs(path):
            raise FileNotFoundError("not a file")
        return os.path.realpath(path)

    @classmethod
    def _download_stat(cls, msg: dict):
        path = cls._download_path(msg)
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode):
            raise FileNotFoundError("not a file")
        return path, info

    @classmethod
    def _open_download(cls, msg: dict):
        path = cls._download_path(msg)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        try:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise FileNotFoundError("not a file")
            return stream, path, info
        except BaseException:
            stream.close()
            raise

    async def _file_stat(self, msg: dict) -> None:
        connection = self.ws
        if connection is None:
            return
        try:
            path, info = await _file_io(self._download_stat, msg)
            reply = {"type": "file-meta", "id": msg.get("id"), "ok": True,
                     "size": info.st_size, "name": os.path.basename(path)}
        except (OSError, ValueError) as exc:
            reply = {"type": "file-meta", "id": msg.get("id"), "ok": False, "error": str(exc)}
        await connection.send_json(reply)

    async def _file_get(self, msg: dict, connection=None, cancelled=None) -> None:
        rid = msg.get("id")
        connection = self.ws if connection is None else connection
        if connection is None:
            return
        cancelled = cancelled or asyncio.Event()
        stream = None
        try:
            stream, path, info = await _file_io(
                self._open_download, msg, cancel_cleanup=lambda opened: opened[0].close())
            if cancelled.is_set() or self.ws is not connection:
                return
            await connection.send_json({"type": "file-meta", "id": rid, "ok": True,
                                        "size": info.st_size, "name": os.path.basename(path)})
            while True:
                if cancelled.is_set() or self.ws is not connection:
                    return
                chunk = await _file_io(stream.read, CHUNK)
                if cancelled.is_set() or self.ws is not connection:
                    return
                if not chunk:
                    break
                await connection.send_binary(KIND_FILE_DATA, rid, chunk)
                await asyncio.sleep(0)
            if not cancelled.is_set() and self.ws is connection:
                await connection.send_json({"type": "file-end", "id": rid})
        except Exception as e:
            if not cancelled.is_set() and self.ws is connection:
                with contextlib.suppress(Exception):
                    await connection.send_json({"type": "file-meta", "id": rid, "ok": False,
                                                "error": str(e)})
        finally:
            if stream is not None:
                await _file_io(stream.close)

    async def _put_start(self, msg: dict) -> None:
        rid = msg.get("id")
        self._abort_upload(rid)
        self._expire_uploads()
        try:
            if len(self.puts) >= MAX_UPLOADS:
                raise ValueError("too many unfinished uploads")
            size = int(msg.get("size", -1))
            self.puts[rid] = await _file_io(
                UploadTransfer, UPLOAD_DIR, msg.get("name", ""), size,
                cancel_cleanup=lambda transfer: transfer.abort())
        except Exception as e:
            await self.send_json({"type": "ack", "id": rid, "ok": False, "error": str(e)})

    async def _put_chunk(self, rid: int, payload: bytes) -> None:
        transfer = self.puts.get(rid)
        if transfer is None:
            return
        try:
            await _file_io(transfer.write, payload)
        except Exception as exc:
            self._abort_upload(rid)
            await self.send_json({"type": "ack", "id": rid, "ok": False, "error": str(exc)})

    async def _put_done(self, msg: dict) -> None:
        rid = msg.get("id")
        transfer = self.puts.pop(rid, None)
        if transfer is None:
            await self.send_json({"type": "ack", "id": rid, "ok": False,
                                  "error": "no such transfer"})
            return
        try:
            path = await _file_io(transfer.finish)
        except Exception as exc:
            await self.send_json({"type": "ack", "id": rid, "ok": False, "error": str(exc)})
            return
        await self.send_json({"type": "ack", "id": rid, "ok": True, "path": path})

    def _abort_upload(self, rid) -> None:
        transfer = self.puts.pop(rid, None)
        if transfer is not None:
            transfer.abort()

    def _expire_uploads(self) -> None:
        now = time.monotonic()
        if now - self._last_upload_sweep < 30:
            return
        self._last_upload_sweep = now
        for rid, transfer in list(self.puts.items()):
            if now - transfer.updated_at > UPLOAD_IDLE_TIMEOUT:
                self._abort_upload(rid)

    async def _reset_transfers(self) -> None:
        tasks = list(self._file_tasks.values())
        for cancelled in self._download_cancels.values():
            cancelled.set()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._file_tasks.clear()
        self._download_cancels.clear()
        for rid in list(self.puts):
            self._abort_upload(rid)


def cleanup_uploads() -> None:
    cleanup_upload_root(UPLOAD_DIR)


async def main() -> None:
    ap = argparse.ArgumentParser(description="tmux-web child node (no tmux required)")
    ap.add_argument("--server", required=True,
                    help="node endpoint, e.g. ws://host:59999/ws-node (always Noise encrypted)")
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
        validate_server_url(args.server)
        validate_node_token(args.token)
    except ValueError as e:
        ap.error(str(e))
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
        cleanup_uploads()
    except (OSError, ValueError) as exc:
        ap.error(f"cannot prepare private upload directory: {type(exc).__name__}")
    try:
        agent = Agent(args.server, args.token, args.name,
                      args.portal_user, args.portal_pass, args.portal_url, args.portal_insecure)
    except CredentialError as exc:
        ap.error(str(exc))
    await agent.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
