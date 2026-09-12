#!/usr/bin/env python3
"""tmux-web: a tiny web UI to select and interact with tmux sessions.

Serves on 0.0.0.0:59999; node application encryption is built in.
  GET  /                     -> web UI (xterm.js)
  GET  /api/sessions         -> JSON list of tmux + child-node sessions
  GET  /api/new?name=...     -> create session (detached); "node:name" on a node
  GET  /api/kill?name=...    -> kill session
  GET  /api/send?name=..&text=.. -> type text into a session (\n = Enter)
  GET  /api/capture?name=..&lines=N -> last N lines of a session's output
  GET  /api/nodes            -> JSON list of connected child nodes + join secret
  GET  /api/stats            -> host metrics (cpu/mem/gpu/net/disk)
  GET  /api/pages            -> JSON list of published pages
  GET  /api/page/del?name=.. -> delete a published page
  GET  /pages/<name>.html    -> serve a published page
  WS   /ws?session=...       -> attach to session via a PTY ("node:name" bridged)
  WS   /ws-upload[?node=..]  -> upload a file, replies with its temp path
  WS   /ws-node?name=..      -> child-node link, Bearer auth (see node.py)

Published pages are plain HTML files dropped into pages/ next to this file
(typically by an agent via the tmux-web-page skill); they expire after 24h.

Child nodes run node.py on machines without tmux; their sessions appear as
"<node>:<name>" everywhere (UI, API, attach, download, upload).

client.py (next to this file) is the official CLI client wrapping this API —
session management, run-and-wait, file up/download; agents should prefer it
over hand-rolling the endpoints above.
"""

import asyncio
import datetime
import fcntl
import getpass
import glob
import http
import json
import os
import pty
import re
import shutil
import signal
import struct
import sys
import subprocess
import tempfile
import termios
import urllib.parse
import hashlib
import secrets
import time

from token_usage import codex_sessions
from hub.runtime import RuntimeConfig
from hub.storage import atomic_json
from hub.targets import split_target
from hub.nodes import NodeConn
from hub.queues import offer_output as _qput
from node import PtyWriter, UploadTransfer, cleanup_upload_root, ensure_private_upload_root

from aiohttp import web
from http_frontend import create_app
from websockets.datastructures import Headers
from websockets.http11 import Response

RUNTIME = RuntimeConfig.from_environment(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = RUNTIME.host, RUNTIME.port
COOKIE_NAME = RUNTIME.cookie_name
BLOCKED_PORTS = RUNTIME.blocked_ports


# ---------------------------------------------------------------------------
# Authentication: salted-hash password file + opaque bearer tokens in a cookie.
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_FILE = str(RUNTIME.state_dir / ".auth.json")
TOKEN_FILE = str(RUNTIME.state_dir / ".tokens.json")
TOKEN_TTL = 30 * 24 * 3600  # 30 days


def node_script_bytes() -> bytes:
    with open(os.path.join(BASE_DIR, "node.py"), "rb") as source:
        return source.read()


def _hash_pw(salt: str, password: str) -> str:
    return hashlib.sha256((salt + "\x00" + password).encode()).hexdigest()


def _load_auth() -> dict:
    try:
        with open(AUTH_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        password = os.environ.get("TMUX_WEB_PASSWORD", "")
        if not password and sys.stdin.isatty():
            password = getpass.getpass("Create tmux-web password (at least 8 characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise RuntimeError("Passwords do not match.")
        if len(password) < 8:
            raise RuntimeError(
                "First start requires a password of at least 8 characters. "
                "Set TMUX_WEB_PASSWORD or run server.py in an interactive terminal."
            )
        auth = {"salt": secrets.token_hex(16)}
        auth["hash"] = _hash_pw(auth["salt"], password)
        _save_json(AUTH_FILE, auth)
        return auth


def _save_json(path: str, data) -> None:
    atomic_json(path, data)


def _load_tokens() -> dict:
    try:
        with open(TOKEN_FILE) as f:
            tokens = json.load(f)
        now = time.time()
        return {t: exp for t, exp in tokens.items() if exp > now}
    except Exception:
        return {}


_AUTH: dict | None = None
_TOKENS: dict = {}
_LOGIN_FAILS: dict[str, tuple[int, float]] = {}  # ip -> (count, blocked_until)


def _auth_state() -> dict:
    global _AUTH
    if _AUTH is None:
        _AUTH = _load_auth()
    return _AUTH


def check_password(password: str) -> bool:
    auth = _auth_state()
    return secrets.compare_digest(_hash_pw(auth["salt"], password), auth["hash"])


def set_password(password: str) -> None:
    auth = _auth_state()
    auth["salt"] = secrets.token_hex(16)
    auth["hash"] = _hash_pw(auth["salt"], password)
    _save_json(AUTH_FILE, auth)


def new_token() -> str:
    token = secrets.token_urlsafe(32)
    _TOKENS[token] = time.time() + TOKEN_TTL
    _save_json(TOKEN_FILE, _TOKENS)
    return token


def request_authed(request) -> bool:
    cookie = request.headers.get("Cookie", "")
    for part in cookie.split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE_NAME and _TOKENS.get(v, 0) > time.time():
            return True
    # Local agents may authenticate with the node secret (readable from
    # .node-secret next to this file) instead of the UI cookie.
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and auth[7:] == node_secret():
        return True
    return False


def node_authed(request, query: dict) -> bool:
    """Use a Bearer header; retain query tokens for existing node deployments."""
    authorization = request.headers.get("Authorization", "")
    if authorization:
        if not authorization.startswith("Bearer "):
            return False
        token = authorization[7:]
    else:
        token = (query.get("token") or [""])[0]
    return bool(token) and secrets.compare_digest(token.encode(), node_secret().encode())


def login_blocked(ip: str) -> bool:
    count, until = _LOGIN_FAILS.get(ip, (0, 0))
    return count >= 5 and time.time() < until


def login_failed(ip: str) -> None:
    count, _ = _LOGIN_FAILS.get(ip, (0, 0))
    _LOGIN_FAILS[ip] = (count + 1, time.time() + 300)  # lock 5 min after 5 fails


def login_succeeded(ip: str) -> None:
    _LOGIN_FAILS.pop(ip, None)


INDEX_HTML = RUNTIME.read_asset("index.html")

LOGIN_HTML = RUNTIME.read_asset("login.html")


def http_response(status: int, body: str, content_type: str, extra: dict | None = None) -> Response:
    headers = {"Content-Type": content_type, "Cache-Control": "no-store"}
    if extra:
        headers.update(extra)
    return Response(status, http.HTTPStatus(status).phrase, Headers(headers), body.encode())


def tmux(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(RUNTIME.tmux_argv(*args), capture_output=True, text=True,
                          timeout=5, env=RUNTIME.tmux_environment())


def list_sessions() -> list:
    out = tmux("list-sessions", "-F", "#{session_name}|#{session_windows}|#{session_attached}")
    sessions = []
    for line in (out.stdout.splitlines() if out.returncode == 0 else []):
        parts = line.rsplit("|", 2)
        if len(parts) != 3:
            continue
        name, wins, attached = parts
        sessions.append({"name": name, "windows": int(wins or 1), "attached": attached == "1"})
    for nname, node in NODES.items():
        for sid, s in node.sessions.items():
            sessions.append({"name": f"{nname}:{s['name']}", "windows": 1,
                             "attached": bool(node.watchers.get(sid)), "node": nname})
    return sessions


VALID_NAME = re.compile(r"^[\w.\-]{1,64}$", re.UNICODE)


# ---------------------------------------------------------------------------
# Published pages: short-lived, self-contained HTML files in pages/ that the
# dashboard shows in its Pages panel. Written directly by local tools (e.g.
# the tmux-web-page skill); swept after PAGE_TTL seconds.
# ---------------------------------------------------------------------------
PAGES_DIR = str(RUNTIME.state_dir / "pages")
PAGE_TTL = 24 * 3600
VALID_PAGE = re.compile(r"^[\w\-]{1,64}\.html$")


def list_pages() -> list:
    out = []
    try:
        names = os.listdir(PAGES_DIR)
    except OSError:
        return out
    for n in names:
        if not VALID_PAGE.match(n):
            continue
        try:
            p = os.path.join(PAGES_DIR, n)
            mtime = os.stat(p).st_mtime
            with open(p, errors="replace") as f:
                head = f.read(4096)
            m = re.search(r"<title[^>]*>(.*?)</title>", head, re.S | re.I)
            title = re.sub(r"\s+", " ", m.group(1)).strip() if m else n[:-5]
            out.append({"name": n, "title": title or n[:-5], "mtime": mtime})
        except OSError:
            pass
    out.sort(key=lambda x: -x["mtime"])
    return out


def _cleanup_pages() -> None:
    try:
        now = time.time()
        for n in os.listdir(PAGES_DIR):
            p = os.path.join(PAGES_DIR, n)
            try:
                if now - os.path.getmtime(p) > PAGE_TTL:
                    os.remove(p)
            except OSError:
                pass
    except OSError:
        pass


async def _page_sweeper() -> None:
    while True:
        await asyncio.sleep(3600)
        _cleanup_pages()
        _cleanup_uploads()


# ---------------------------------------------------------------------------
# Kimi CLI token usage, aggregated per day from the local session wire files.
# Results are memoized per file by mtime so repeat polls only re-read files
# that changed.
# ---------------------------------------------------------------------------
KIMI_SESSIONS_DIR = os.path.expanduser("~/.kimi-code/sessions")
TOKEN_KEYS = ("inputOther", "inputCacheRead", "inputCacheCreation", "output")
_token_cache: dict[str, tuple[float, dict]] = {}  # wire path -> (mtime, {date: usage})


def _wire_daily(path: str, mtime: float) -> dict:
    cached = _token_cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    per: dict[str, dict] = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                if '"usage"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                u = d.get("event", {}).get("usage") or d.get("usage")
                t = d.get("time") or d.get("event", {}).get("time")
                if not u or not t:
                    continue
                day = datetime.datetime.fromtimestamp(t / 1000).date().isoformat()
                a = per.setdefault(day, dict.fromkeys(TOKEN_KEYS, 0) | {"steps": 0})
                a["steps"] += 1
                for k in TOKEN_KEYS:
                    a[k] += u.get(k, 0)
    except OSError:
        pass
    _token_cache[path] = (mtime, per)
    return per


def _kimi_token_stats(days: int = 30) -> dict:
    today = datetime.date.today()
    cutoff = today - datetime.timedelta(days=days - 1)
    cutoff_ts = time.mktime(cutoff.timetuple())
    merged: dict[str, dict] = {}
    for wf in glob.glob(os.path.join(KIMI_SESSIONS_DIR, "*", "session_*", "agents", "*", "wire.jsonl")):
        try:
            mtime = os.stat(wf).st_mtime
        except OSError:
            continue
        if mtime < cutoff_ts - 86400:
            continue  # untouched for the whole window: nothing to contribute
        for day, a in _wire_daily(wf, mtime).items():
            if day < cutoff.isoformat():
                continue
            b = merged.setdefault(day, dict.fromkeys(TOKEN_KEYS, 0))
            for k in TOKEN_KEYS:
                b[k] += a[k]
    return {
        "types": list(TOKEN_KEYS),
        "days": [
            {"date": (cutoff + datetime.timedelta(days=i)).isoformat(),
             **merged.get((cutoff + datetime.timedelta(days=i)).isoformat(),
                          dict.fromkeys(TOKEN_KEYS, 0))}
            for i in range(days)
        ],
    }


def _kimi_token_day(date: str) -> dict:
    """Per-session usage breakdown for one day (YYYY-MM-DD)."""
    day_start = time.mktime(datetime.date.fromisoformat(date).timetuple())
    sessions: dict[str, dict] = {}
    totals = dict.fromkeys(TOKEN_KEYS, 0) | {"steps": 0}
    for wf in glob.glob(os.path.join(KIMI_SESSIONS_DIR, "*", "session_*", "agents", "*", "wire.jsonl")):
        try:
            mtime = os.stat(wf).st_mtime
        except OSError:
            continue
        if mtime < day_start:
            continue  # last modified before this day: cannot contain it
        a = _wire_daily(wf, mtime).get(date)
        if not a:
            continue
        sess_dir = os.path.dirname(os.path.dirname(os.path.dirname(wf)))
        sid = sess_dir.split("session_")[-1]
        s = sessions.setdefault(sid, dict.fromkeys(TOKEN_KEYS, 0) | {"steps": 0})
        s["steps"] += a["steps"]
        for k in TOKEN_KEYS:
            s[k] += a[k]
            totals[k] += a[k]
        totals["steps"] += a["steps"]

    out = []
    for sid, s in sessions.items():
        sess_dir = os.path.join(KIMI_SESSIONS_DIR, "*", f"session_{sid}")
        title, cwd = "", ""
        for d in glob.glob(sess_dir):
            try:
                meta = json.load(open(os.path.join(d, "state.json")))
                title = meta.get("title") or meta.get("lastPrompt") or ""
                cwd = meta.get("cwd") or ""
            except Exception:
                pass
            break
        out.append({"id": sid, "title": title[:80], "cwd": cwd, "steps": s["steps"],
                    **{k: s[k] for k in TOKEN_KEYS}})
    out.sort(key=lambda x: -(x["inputOther"] + x["inputCacheRead"] + x["output"]))
    return {"date": date, "totals": totals, "sessions": out}


_token_lock = asyncio.Lock()


def token_stats(days: int = 30, source: str = "kimi") -> dict:
    result = _kimi_token_stats(days) if source != "codex" else {
        "types": list(TOKEN_KEYS),
        "days": [{"date": (datetime.date.today() - datetime.timedelta(days=i)).isoformat(),
                  **dict.fromkeys(TOKEN_KEYS, 0)} for i in reversed(range(days))],
    }
    if source != "kimi":
        rows = {d["date"]: d for d in result["days"]}
        for s in codex_sessions(result["days"][0]["date"]):
            for date, usage in s["days"].items():
                if date in rows:
                    for k in TOKEN_KEYS:
                        rows[date][k] += usage[k]
    result["source"] = source
    return result


def token_day(date: str, source: str = "kimi") -> dict:
    datetime.date.fromisoformat(date)
    result = _kimi_token_day(date) if source != "codex" else {
        "date": date, "totals": dict.fromkeys(TOKEN_KEYS, 0) | {"steps": 0}, "sessions": [],
    }
    for s in result["sessions"]:
        s["provider"] = "kimi"
    if source != "kimi":
        for s in codex_sessions(date):
            usage = s["days"].get(date)
            if usage:
                result["sessions"].append({k: v for k, v in s.items() if k != "days"} | usage)
                for k in (*TOKEN_KEYS, "steps"):
                    result["totals"][k] += usage[k]
    result["sessions"].sort(key=lambda s: -sum(s[k] for k in TOKEN_KEYS))
    result["source"] = source
    return result


# ---------------------------------------------------------------------------
# Host metrics for the monitor panel. CPU % and NIC rates need two samples,
# so the previous readings are kept between /api/stats calls.
# ---------------------------------------------------------------------------
_prev_cpu: tuple[int, int] | None = None   # (total jiffies, idle jiffies)
_prev_net: tuple[float, dict] | None = None  # (timestamp, {iface: (rx, tx)})


def _read_cpu() -> tuple[int, int]:
    with open("/proc/stat") as f:
        vals = [int(x) for x in f.readline().split()[1:]]
    return sum(vals), vals[3] + vals[4]  # total, idle+iowait


def _read_mem() -> dict:
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, v = line.partition(":")
            info[k] = int(v.split()[0]) * 1024
    total = info["MemTotal"]
    avail = info.get("MemAvailable", 0)
    stotal = info.get("SwapTotal", 0)
    return {
        "total": total, "used": total - avail,
        "swap_total": stotal, "swap_used": stotal - info.get("SwapFree", 0),
    }


def _read_net() -> dict:
    out = {}
    with open("/proc/net/dev") as f:
        for line in f.readlines()[2:]:
            name, _, rest = line.partition(":")
            name = name.strip()
            if name == "lo":
                continue
            fields = rest.split()
            out[name] = (int(fields[0]), int(fields[8]))  # rx bytes, tx bytes
    return out


def _read_gpus() -> list:
    try:
        r = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return []
        gpus = []
        for line in r.stdout.strip().splitlines():
            idx, name, util, mu, mt, temp, pw = [p.strip() for p in line.split(",")]
            gpus.append({
                "index": idx, "name": name,
                "util": float(util), "mem_used": float(mu) * 2**20,
                "mem_total": float(mt) * 2**20, "temp": float(temp),
                "power": float(pw) if pw not in ("N/A", "") else None,
            })
        return gpus
    except Exception:
        return []


_FS_TYPES = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "ntfs", "vfat", "exfat", "f2fs"}


def _read_disks() -> list:
    seen, out = set(), []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                dev, mp, fstype = line.split()[:3]
                if fstype not in _FS_TYPES or dev in seen:
                    continue
                try:
                    u = shutil.disk_usage(mp)
                except OSError:
                    continue
                seen.add(dev)
                out.append({"mount": mp, "total": u.total, "used": u.used})
    except OSError:
        pass
    return out[:8]


def collect_stats() -> dict:
    global _prev_cpu, _prev_net
    now = time.time()

    total, idle = _read_cpu()
    cpu_pct = 0.0
    if _prev_cpu:
        dt, di = total - _prev_cpu[0], idle - _prev_cpu[1]
        if dt > 0:
            cpu_pct = max(0.0, min(100.0, 100.0 * (1 - di / dt)))
    _prev_cpu = (total, idle)

    net = _read_net()
    rates = []
    if _prev_net:
        pt, pn = _prev_net
        el = max(now - pt, 1e-6)
        for k, (rx, tx) in net.items():
            if k in pn:
                rates.append({"iface": k,
                              "rx": max(0, rx - pn[k][0]) / el,
                              "tx": max(0, tx - pn[k][1]) / el})
    _prev_net = (now, net)

    try:
        load = list(os.getloadavg())
    except OSError:
        load = [0.0, 0.0, 0.0]
    try:
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
    except OSError:
        uptime = 0.0

    return {
        "host": os.uname().nodename,
        "uptime": uptime,
        "cpu": {"pct": cpu_pct, "cores": os.cpu_count() or 1, "load": load},
        "mem": _read_mem(),
        "gpus": _read_gpus(),
        "net": rates,
        "disks": _read_disks(),
    }


async def process_request(connection, request):
    url = urllib.parse.urlsplit(request.path)
    path, query = url.path, urllib.parse.parse_qs(url.query)

    if path == "/node.py":
        return http_response(200, node_script_bytes().decode("utf-8"), "text/x-python; charset=utf-8")

    if path == "/api/login":
        ip = (connection.remote_address or ("?",))[0]
        if login_blocked(ip):
            return http_response(429, "too many attempts, try again later\n", "text/plain; charset=utf-8")
        if check_password((query.get("password") or [""])[0]):
            login_succeeded(ip)
            cookie = (f"{COOKIE_NAME}={new_token()}; Max-Age={TOKEN_TTL}; "
                      "Path=/; HttpOnly; SameSite=Strict")
            if getattr(request, "secure", False):
                cookie += "; Secure"
            return http_response(200, "ok\n", "text/plain; charset=utf-8",
                                 {"Set-Cookie": cookie})
        login_failed(ip)
        return http_response(401, "wrong password\n", "text/plain; charset=utf-8")

    if path == "/ws-node":
        if query.get("v") == ["2"]:
            # Authenticate inside Noise before registering a node. No secret or
            # node/session metadata belongs in the unencrypted HTTP handshake.
            if "name" in query or "token" in query or request.headers.get("Authorization"):
                return http_response(400, "credentials must be sent inside the encrypted channel\n", "text/plain")
            return None
        # Child nodes authenticate with the node secret, not the UI cookie.
        if (not node_authed(request, query)
                or not VALID_NODE.match((query.get("name") or [""])[0])):
            return http_response(401, "unauthorized\n", "text/plain; charset=utf-8")
        return None  # proceed with the websocket handshake

    if path == "/ws-relay":
        # TCP-over-WS relay for child nodes; same node-secret auth as /ws-node.
        if not node_authed(request, query):
            return http_response(401, "unauthorized\n", "text/plain; charset=utf-8")
        return None  # proceed with the websocket handshake

    if not request_authed(request):
        if path == "/":
            return http_response(200, LOGIN_HTML, "text/html; charset=utf-8")
        return http_response(401, "unauthorized\n", "text/plain; charset=utf-8")

    if path == "/":
        return http_response(200, INDEX_HTML, "text/html; charset=utf-8")

    if path in ("/api/kill", "/api/send", "/api/capture", "/ws"):
        target = (query.get("session" if path == "/ws" else "name") or [""])[0]
        try:
            target_node, _ = split_node(target)
        except ValueError:
            return http_response(400, "invalid session name\n", "text/plain; charset=utf-8")
        if target_node and target_node not in NODES:
            return http_response(404, "node not connected\n", "text/plain; charset=utf-8")

    if path == "/api/passwd":
        old = (query.get("old") or [""])[0]
        new = (query.get("new") or [""])[0]
        if not check_password(old):
            return http_response(403, "current password incorrect\n", "text/plain; charset=utf-8")
        if not 6 <= len(new) <= 128:
            return http_response(400, "new password must be 6-128 characters\n", "text/plain; charset=utf-8")
        set_password(new)
        return http_response(200, "ok\n", "text/plain; charset=utf-8")

    if path == "/api/sessions":
        return http_response(200, json.dumps(list_sessions()), "application/json")

    if path == "/api/new":
        name = (query.get("name") or [""])[0]
        m = re.match(r"^(?:([\w.\-]{1,32}):)?([\w.\-]{1,64})$", name, re.UNICODE)
        if not m:
            return http_response(400, "invalid session name\n", "text/plain; charset=utf-8")
        nname, sname = m.group(1), m.group(2)
        if nname:
            node = NODES.get(nname)
            if not node:
                return http_response(404, "node not connected\n", "text/plain; charset=utf-8")
            if node.sid_by_name(sname) is not None:
                return http_response(409, "session exists on node\n", "text/plain; charset=utf-8")
            try:
                r = await node.request({"type": "new", "name": sname, "cols": 220, "rows": 50})
            except Exception as e:
                return http_response(502, f"node error: {e}\n", "text/plain; charset=utf-8")
            if not r.get("ok"):
                return http_response(409, (r.get("error") or "failed") + "\n", "text/plain; charset=utf-8")
            node.sessions[int(r["sid"])] = {"name": sname, "cols": 220, "rows": 50}
            return http_response(200, "ok\n", "text/plain; charset=utf-8")
        r = tmux("new-session", "-d", "-s", sname, "-x", "220", "-y", "50")
        if r.returncode != 0:
            return http_response(409, r.stderr or "failed\n", "text/plain; charset=utf-8")
        return http_response(200, "ok\n", "text/plain; charset=utf-8")

    if path == "/api/kill":
        name = (query.get("name") or [""])[0]
        nname, sname = split_node(name)
        if nname:
            node = NODES[nname]
            sid = node.sid_by_name(sname)
            if sid is None:
                return http_response(404, "no such session on node\n", "text/plain; charset=utf-8")
            try:
                r = await node.request({"type": "kill", "sid": sid})
            except Exception as e:
                return http_response(502, f"node error: {e}\n", "text/plain; charset=utf-8")
            if not r.get("ok"):
                return http_response(404, (r.get("error") or "failed") + "\n", "text/plain; charset=utf-8")
            node.sessions.pop(sid, None)
            return http_response(200, "ok\n", "text/plain; charset=utf-8")
        r = tmux("kill-session", "-t", name)
        if r.returncode != 0:
            return http_response(404, r.stderr or "failed\n", "text/plain; charset=utf-8")
        return http_response(200, "ok\n", "text/plain; charset=utf-8")

    if path == "/api/send":
        name = (query.get("name") or [""])[0]
        text = (query.get("text") or [""])[0]
        nname, sname = split_node(name)
        if nname:
            node = NODES[nname]
            sid = node.sid_by_name(sname)
            if sid is None:
                return http_response(404, "no such session on node\n", "text/plain; charset=utf-8")
            node.send_input(sid, text.encode().replace(b"\n", b"\r"))
            return http_response(200, "ok\n", "text/plain; charset=utf-8")
        parts = text.split("\n")
        for i, part in enumerate(parts):
            if part:
                r = tmux("send-keys", "-t", name, "-l", "--", part)
                if r.returncode != 0:
                    return http_response(404, r.stderr or "failed\n", "text/plain; charset=utf-8")
            if i < len(parts) - 1:
                tmux("send-keys", "-t", name, "Enter")
        return http_response(200, "ok\n", "text/plain; charset=utf-8")

    if path == "/api/capture":
        name = (query.get("name") or [""])[0]
        try:
            lines = max(1, min(int((query.get("lines") or ["50"])[0]), 2000))
        except ValueError:
            lines = 50
        nname, sname = split_node(name)
        if nname:
            node = NODES[nname]
            sid = node.sid_by_name(sname)
            if sid is None:
                return http_response(404, "no such session on node\n", "text/plain; charset=utf-8")
            try:
                r = await node.request({"type": "capture", "sid": sid, "lines": lines})
            except Exception as e:
                return http_response(502, f"node error: {e}\n", "text/plain; charset=utf-8")
            if not r.get("ok"):
                return http_response(404, (r.get("error") or "failed") + "\n", "text/plain; charset=utf-8")
            return http_response(200, r.get("text", ""), "text/plain; charset=utf-8")
        r = tmux("capture-pane", "-p", "-t", name, "-S", str(-lines))
        if r.returncode != 0:
            return http_response(404, r.stderr or "failed\n", "text/plain; charset=utf-8")
        return http_response(200, r.stdout, "text/plain; charset=utf-8")

    if path == "/api/nodes":
        return http_response(200, json.dumps({
            "secret": node_secret(),
            "node_script_sha256": hashlib.sha256(node_script_bytes()).hexdigest(),
            "port": PORT,
            "nodes": [{"name": n, "sessions": len(c.sessions),
                       "encrypted": getattr(c, "encrypted", False)} for n, c in NODES.items()],
        }), "application/json")

    if path == "/api/stats":
        return http_response(200, json.dumps(collect_stats()), "application/json")

    if path in ("/api/tokens", "/api/tokens/day"):
        source = (query.get("source") or ["kimi"])[0]
        if source not in ("kimi", "codex", "all"):
            return http_response(400, "bad source\n", "text/plain; charset=utf-8")
        try:
            if path == "/api/tokens":
                arg = max(1, min(int((query.get("days") or ["30"])[0]), 90))
                fn = token_stats
            else:
                arg = (query.get("date") or [""])[0]
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", arg):
                    raise ValueError("bad date")
                datetime.date.fromisoformat(arg)
                fn = token_day
        except ValueError:
            return http_response(400, "bad days or date\n", "text/plain; charset=utf-8")
        async with _token_lock:
            result = await asyncio.to_thread(fn, arg, source)
        return http_response(200, json.dumps(result), "application/json")

    if path == "/api/pages":
        return http_response(200, json.dumps(list_pages()), "application/json")

    if path == "/api/page/del":
        name = (query.get("name") or [""])[0]
        if not VALID_PAGE.match(name):
            return http_response(400, "invalid page name\n", "text/plain; charset=utf-8")
        try:
            os.remove(os.path.join(PAGES_DIR, name))
        except OSError:
            return http_response(404, "no such page\n", "text/plain; charset=utf-8")
        return http_response(200, "ok\n", "text/plain; charset=utf-8")

    if path.startswith("/pages/"):
        name = path[len("/pages/"):]
        if not VALID_PAGE.match(name):
            return http_response(404, "not found\n", "text/plain; charset=utf-8")
        try:
            with open(os.path.join(PAGES_DIR, name)) as f:
                body = f.read()
        except OSError:
            return http_response(404, "not found\n", "text/plain; charset=utf-8")
        return http_response(200, body, "text/html; charset=utf-8")

    if path == "/api/resolve-path":
        # Used by the web UI to disambiguate paths that wrap across terminal
        # lines: the client glues continuation lines together, which may tack
        # junk (e.g. the next shell prompt) onto the path. Trim the candidate
        # to the longest prefix that is an existing regular file.
        p = (query.get("path") or [""])[0]
        nname = (query.get("node") or [""])[0]
        if nname:
            node = NODES.get(nname)
            if not node:
                return http_response(404, json.dumps({"ok": False}), "application/json")
            try:
                r = await node.request({"type": "resolve", "path": p})
            except Exception:
                return http_response(502, json.dumps({"ok": False}), "application/json")
            if not r.get("ok"):
                return http_response(404, json.dumps({"ok": False}), "application/json")
            return http_response(200, json.dumps(
                {"ok": True, "path": r.get("path", ""), "name": r.get("name", "")}),
                "application/json")
        if p.startswith("~"):
            p = os.path.expanduser(p)
        if not p.startswith("/"):
            return http_response(400, "need an absolute path\n", "text/plain; charset=utf-8")
        q = p
        found = None
        for _ in range(2048):
            if len(q) < 3:
                break
            if os.path.isfile(os.path.realpath(q)):
                found = q
                break
            q = q[:-1]
        if found is None:
            return http_response(404, json.dumps({"ok": False}), "application/json")
        return http_response(200, json.dumps(
            {"ok": True, "path": found, "name": os.path.basename(os.path.realpath(found))}),
            "application/json")

    if path == "/api/download":
        p = (query.get("path") or [""])[0]
        nname = (query.get("node") or [""])[0]
        if nname:
            node = NODES.get(nname)
            if not node:
                return http_response(404, "node not connected\n", "text/plain; charset=utf-8")
            if (query.get("check") or [""])[0] == "1":
                try:
                    meta = await node.file_stat(p)
                except Exception as error:
                    return http_response(502, f"node error: {error}\n", "text/plain; charset=utf-8")
                if not meta.get("ok"):
                    return http_response(404, "not a file\n", "text/plain; charset=utf-8")
                return http_response(200, json.dumps({"ok": True, "size": int(meta.get("size", 0)),
                                                     "name": meta.get("name", "file")}), "application/json")
            try:
                meta, rid, q = await node.file_get(p)
            except Exception as e:
                return http_response(502, f"node error: {e}\n", "text/plain; charset=utf-8")
            if not meta.get("ok"):
                return http_response(404, (meta.get("error") or "not a file") + "\n",
                                     "text/plain; charset=utf-8")
            if (query.get("check") or [""])[0] == "1":
                node.file_queues.pop(rid, None)
                return http_response(200, json.dumps(
                    {"ok": True, "size": int(meta.get("size", 0)),
                     "name": meta.get("name", "file")}), "application/json")
            data, complete = await node.file_collect(rid, q, 1024**3)
            if not complete:
                return http_response(413, "file too large (max 1 GiB)\n",
                                     "text/plain; charset=utf-8")
            if len(data) != int(meta.get("size", -1)):
                return http_response(502, "incomplete node file transfer\n", "text/plain; charset=utf-8")
            name = os.path.basename(meta.get("name", "")) or "file"
            return Response(200, http.HTTPStatus(200).phrase, Headers({
                "Content-Type": "application/octet-stream",
                "Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(name),
                "Cache-Control": "no-store",
            }), data)
        if p.startswith("~"):
            p = os.path.expanduser(p)
        if not p.startswith("/"):
            return http_response(400, "need an absolute path\n", "text/plain; charset=utf-8")
        rp = os.path.realpath(p)
        if not os.path.isfile(rp):
            return http_response(404, "not a file\n", "text/plain; charset=utf-8")
        if (query.get("check") or [""])[0] == "1":
            return http_response(200, json.dumps(
                {"ok": True, "size": os.path.getsize(rp), "name": os.path.basename(rp)}),
                "application/json")
        try:
            size = os.path.getsize(rp)
            if size > 1024**3:
                return http_response(413, "file too large (max 1 GiB)\n", "text/plain; charset=utf-8")
            with open(rp, "rb") as f:
                data = f.read()
        except OSError:
            return http_response(403, "unreadable\n", "text/plain; charset=utf-8")
        name = os.path.basename(rp) or "file"
        return Response(200, http.HTTPStatus(200).phrase, Headers({
            "Content-Type": "application/octet-stream",
            "Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(name),
            "Cache-Control": "no-store",
        }), data)

    if path == "/ws":
        return None  # proceed with the websocket handshake

    if path == "/ws-upload":
        return None  # websocket file upload

    return http_response(404, "not found\n", "text/plain; charset=utf-8")


def set_winsize(fd: int, cols: int, rows: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


# Per-session web-client bookkeeping: while at least one web client is
# attached, enable tmux mouse mode so the wheel/touch scroll works.
# The session's original setting is restored when the last client leaves.
#
# Size ownership: tmux's window-size=latest lets ANY attached client (a
# phone tab, a real terminal) hijack the shared window size, leaving every
# other client staring at a viewport full of dots. To keep the web view
# stable, the most recently active web client is the size "owner" and a
# per-session watchdog forces the window back to the owner's size.
_attach_state: dict[str, dict] = {}
# Last terminal size reported by a web client, per session.
_last_size: dict[str, tuple[int, int]] = {}


def _tmux_out(*args: str) -> str:
    r = tmux(*args)
    return r.stdout.strip() if r.returncode == 0 else ""


def _status_lines(name: str) -> int:
    # session-level value is empty unless explicitly set; fall back to global
    v = _tmux_out("show-option", "-t", name, "-v", "status") or \
        _tmux_out("show-option", "-gv", "status")
    if v in ("", "off"):
        return 1 if v == "" else 0
    if v == "on":
        return 1
    try:
        return int(v)
    except ValueError:
        return 1


def _apply_size(name: str, st: dict) -> None:
    """Resize the session's current window to the size owner's dimensions."""
    cid = st.get("owner")
    size = st["sizes"].get(cid) if cid is not None else None
    if not size:
        return
    cols, rows = size
    nname, sname = split_node(name)
    if nname:
        node = NODES.get(nname)
        sid = node.sid_by_name(sname) if node else None
        if node and sid is not None:
            asyncio.create_task(node.set_size(sid, cols, rows))
        return
    tmux("resize-window", "-t", name, "-x", str(cols),
         "-y", str(max(1, rows - st.get("status_lines", 1))))


async def _size_watchdog(name: str) -> None:
    try:
        while True:
            await asyncio.sleep(2)
            st = _attach_state.get(name)
            if not st or st["count"] <= 0:
                return
            if split_node(name)[0]:
                # Node sessions own their pty outright: no competing clients,
                # just keep the owner's size applied (e.g. after a node
                # reconnect creates a fresh attach).
                _apply_size(name, st)
                continue
            st["status_lines"] = _status_lines(name)
            cid = st.get("owner")
            size = st["sizes"].get(cid) if cid is not None else None
            if not size:
                continue
            cols, rows = size
            want = (cols, max(1, rows - st["status_lines"]))
            cur = ""
            for line in _tmux_out(
                    "list-windows", "-t", name,
                    "-F", "#{window_active} #{window_width} #{window_height}").splitlines():
                if line.startswith("1 "):
                    cur = line[2:]
                    break
            try:
                got = tuple(int(x) for x in cur.split())
            except ValueError:
                continue
            if got != want:
                tmux("resize-window", "-t", name, "-x", str(want[0]), "-y", str(want[1]))
    except asyncio.CancelledError:
        pass


def web_attach(name: str, cid: int, cols: int, rows: int) -> None:
    st = _attach_state.setdefault(name, {"count": 0, "orig": None})
    if st["count"] == 0:
        if split_node(name)[0]:
            st["orig"] = None  # no tmux options on node sessions
            st["status_lines"] = 0
        else:
            r = tmux("show-option", "-t", name, "-v", "mouse")
            st["orig"] = r.stdout.strip() if r.returncode == 0 else "off"
            tmux("set-option", "-t", name, "mouse", "on")
            st["status_lines"] = _status_lines(name)
        st["sizes"] = {}
        st["owner"] = None
        st["watchdog"] = asyncio.create_task(_size_watchdog(name))
    st["count"] += 1
    st["sizes"][cid] = (cols, rows)
    st["owner"] = cid  # newest attach takes ownership
    _apply_size(name, st)


def web_resize(name: str, cid: int, cols: int, rows: int) -> None:
    st = _attach_state.get(name)
    if not st:
        return
    st["sizes"][cid] = (cols, rows)
    st["owner"] = cid  # actively resizing a browser: that client owns the size
    _apply_size(name, st)


def web_detach(name: str, cid: int) -> None:
    st = _attach_state.get(name)
    if not st:
        return
    st["count"] -= 1
    st["sizes"].pop(cid, None)
    if st["count"] <= 0:
        wd = st.get("watchdog")
        if wd:
            wd.cancel()
        _attach_state.pop(name, None)
        if st["orig"] == "off":
            tmux("set-option", "-t", name, "mouse", "off")
    elif st["owner"] == cid:
        # Owner left: hand ownership to a remaining client and snap the
        # window to its size.
        st["owner"] = next(iter(st["sizes"]), None)
        _apply_size(name, st)


# ---------------------------------------------------------------------------
# Child nodes: remote machines running node.py connect over /ws-node and
# expose tmux-like sessions as "<node>:<name>". The link is a single
# websocket: text frames carry JSON control messages, binary frames carry
# stream/file data as [kind:1B][id:8B big-endian][payload].
# ---------------------------------------------------------------------------
NODE_SECRET_FILE = str(RUNTIME.state_dir / ".node-secret")
NODE_PROTO_VERSION = 2
VALID_NODE = re.compile(r"^[\w.\-]{1,32}$", re.UNICODE)

KIND_OUTPUT = 0     # node -> hub: terminal output (id = session id)
KIND_INPUT = 1      # hub -> node: terminal input (id = session id)
KIND_FILE_DATA = 2  # node -> hub: file-get chunk (id = request id)
KIND_FILE_PUT = 3   # hub -> node: file-put chunk (id = request id)

NODES: dict[str, "NodeConn"] = {}


def node_secret() -> str:
    try:
        with open(NODE_SECRET_FILE) as f:
            s = f.read().strip()
            if s:
                return s
    except OSError:
        pass
    s = secrets.token_hex(16)
    with open(NODE_SECRET_FILE, "w") as f:
        f.write(s + "\n")
    os.chmod(NODE_SECRET_FILE, 0o600)
    return s


def split_node(name: str):
    """Parse the namespace independently of connection availability."""
    return split_target(name)


async def handle_node_ws(ws) -> None:
    url = urllib.parse.urlsplit(ws.request.path)
    query = urllib.parse.parse_qs(url.query)
    name = (query.get("name") or [""])[0]
    encrypted = query.get("v") == ["2"]
    try:
        if encrypted:
            from node import NoiseChannel
            ws = await asyncio.wait_for(NoiseChannel.establish(ws, node_secret(), initiator=False), 10)
        raw = await asyncio.wait_for(ws.recv(), 15)
        hello = json.loads(raw) if isinstance(raw, str) else {}
        if hello.get("type") != "hello":
            raise ValueError("expected hello")
        if encrypted:
            name = hello.get("name", "")
            if hello.get("version") != NODE_PROTO_VERSION or not isinstance(name, str) or not VALID_NODE.fullmatch(name):
                raise ValueError("invalid encrypted node registration")
        node = NodeConn(ws, name)
        node.encrypted = encrypted
        features = hello.get("capabilities", [])
        if isinstance(features, list):
            node.capabilities = frozenset(value for value in features if isinstance(value, str))
        for s in hello.get("sessions", []):
            node.sessions[int(s["sid"])] = {
                "name": str(s.get("name", ""))[:64],
                "cols": int(s.get("cols", 220)), "rows": int(s.get("rows", 50))}
    except (ValueError, KeyError, TypeError, ConnectionError, asyncio.TimeoutError):
        await ws.close(1008, "node authentication failed")
        return
    if name in NODES:
        await ws.close(1008, "node name already connected")
        return
    NODES[name] = node
    try:
        await node.send_json({"type": "hello-ok", "version": NODE_PROTO_VERSION})
        async for msg in ws:
            if isinstance(msg, str):
                await node.handle_text(json.loads(msg))
            elif len(msg) >= 9:
                kind, rid = msg[0], int.from_bytes(msg[1:9], "big")
                payload = bytes(msg[9:])
                if kind == KIND_OUTPUT:
                    for q in list(node.watchers.get(rid, ())):
                        _qput(q, payload)
                elif kind == KIND_FILE_DATA:
                    q = node.file_queues.get(rid)
                    if q is not None:
                        await q.put(payload)
    except (ValueError, KeyError, TypeError, ConnectionError):
        pass
    finally:
        if NODES.get(name) is node:
            NODES.pop(name, None)
        await node.close()


async def handle_node_attach(ws, node: NodeConn, key: str, sname: str) -> None:
    """Bridge a web client's websocket to a session living on a child node."""
    sid = node.sid_by_name(sname)
    if sid is None:
        await ws.close(4004, "no such session on node")
        return
    cols, rows = _last_size.get(key, (220, 50))
    cid = id(ws)
    queue: asyncio.Queue = asyncio.Queue(maxsize=256)
    watches = node.watchers.setdefault(sid, set())

    async def node_to_ws() -> None:
        while True:
            item = await queue.get()
            if item is None:
                break
            await ws.send(item)

    async def ws_to_node() -> None:
        async for msg in ws:
            if isinstance(msg, str):
                try:
                    ctl = json.loads(msg)
                except ValueError:
                    continue
                if ctl.get("type") == "resize":
                    c = max(1, min(int(ctl.get("cols", 220)), 1000))
                    r = max(1, min(int(ctl.get("rows", 50)), 1000))
                    _last_size[key] = (c, r)
                    web_resize(key, cid, c, r)
            else:
                # Typing means this client owns the size (same rule as local).
                st = _attach_state.get(key)
                if st and st.get("owner") != cid:
                    st["owner"] = cid
                    _apply_size(key, st)
                node.send_input(sid, bytes(msg))

    tasks = []
    try:
        web_attach(key, cid, cols, rows)
        watches.add(queue)
        if len(watches) == 1:
            await node.send_json({"type": "watch", "sid": sid, "cols": cols, "rows": rows})
        tasks = [asyncio.create_task(node_to_ws()), asyncio.create_task(ws_to_node())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        watches.discard(queue)
        if not watches:
            node.watchers.pop(sid, None)
            try:
                await node.send_json({"type": "unwatch", "sid": sid})
            except Exception:
                pass
        try:
            web_detach(key, cid)
        except Exception as error:
            print(f"terminal detach cleanup failed: {type(error).__name__}", file=sys.stderr)


# ---------------------------------------------------------------------------
# File upload over a dedicated websocket: client sends a JSON header
# {"name": ..., "size": ...}, then raw binary frames until <size> bytes have
# been sent; the server replies {"ok": true, "path": ...}.
# With ?node=<name> the file lands on that child node instead.
# ---------------------------------------------------------------------------
UPLOAD_DIR = RUNTIME.upload_dir
MAX_UPLOAD = 2 * 1024**3  # 2 GiB


def _safe_name(name: str) -> str:
    name = os.path.basename(name).strip()[:128]
    if name in ("", ".", ".."):
        name = "file"
    return name


def _cleanup_uploads() -> None:
    cleanup_upload_root(UPLOAD_DIR)


async def handle_upload(ws) -> None:
    url = urllib.parse.urlsplit(ws.request.path)
    query = urllib.parse.parse_qs(url.query)
    try:
        raw = await asyncio.wait_for(ws.recv(), 15)
        meta = json.loads(raw) if isinstance(raw, str) else {}
        name = _safe_name(str(meta.get("name", "")))
        size = int(meta.get("size", -1))
        if not 0 <= size <= MAX_UPLOAD:
            raise ValueError("bad size")
    except Exception:
        await ws.send(json.dumps({"ok": False, "error": "bad upload header"}))
        await ws.close()
        return

    nname = (query.get("node") or [""])[0]
    if nname:
        await _handle_node_upload(ws, nname, name, size)
        return

    transfer = None
    complete = False
    try:
        transfer = UploadTransfer(UPLOAD_DIR, name, size)
        while transfer.received < size:
            message = await asyncio.wait_for(ws.recv(), 60)
            if not isinstance(message, (bytes, bytearray)):
                raise ValueError("expected upload data")
            transfer.write(bytes(message))
        path = transfer.finish()
        complete = True
        await ws.send(json.dumps({"ok": True, "path": path, "size": size}))
    except asyncio.CancelledError:
        raise
    except Exception as error:
        try:
            await ws.send(json.dumps({"ok": False, "error": str(error)}))
        except Exception:
            pass
    finally:
        if transfer is not None and not complete:
            transfer.abort()
        await ws.close()


async def _handle_node_upload(ws, nname: str, name: str, size: int) -> None:
    """Forward an upload stream to a child node; it stores the file and
    replies with the temp path on the remote machine."""
    node = NODES.get(nname)
    if not node:
        await ws.send(json.dumps({"ok": False, "error": "node not connected"}))
        await ws.close()
        return
    rid = node._req_id()
    fut = asyncio.get_running_loop().create_future()
    node.pending[rid] = fut
    terminal = False
    try:
        await node.send_json({"type": "file-put", "id": rid, "name": name, "size": size})
        received = 0
        while received < size:
            msg = await asyncio.wait_for(ws.recv(), 60)
            if not isinstance(msg, (bytes, bytearray)):
                raise ValueError("expected upload data")
            if len(msg) > size - received:
                raise ValueError("upload exceeds declared size")
            # Bound the application-message lock even when a browser sends a
            # multi-megabyte WS frame. All previous node versions accept chunks.
            for offset in range(0, len(msg), 32768):
                await node.ws.send(bytes([KIND_FILE_PUT]) + rid.to_bytes(8, "big") + bytes(msg[offset:offset + 32768]))
                await asyncio.sleep(0)
            received += len(msg)
        await node.send_json({"type": "file-put-done", "id": rid})
        r = await asyncio.wait_for(fut, 300)
        terminal = True
        if r.get("ok"):
            await ws.send(json.dumps({"ok": True, "path": r.get("path", ""), "size": received}))
        else:
            await ws.send(json.dumps({"ok": False, "error": r.get("error", "node upload failed")}))
    except asyncio.CancelledError:
        raise
    except Exception as e:
        try:
            await ws.send(json.dumps({"ok": False, "error": str(e)}))
        except Exception:
            pass
    finally:
        if not terminal and not node.closed:
            try:
                kind = "file-put-abort" if "file-put-abort" in node.capabilities else "file-put-done"
                await node.send_json({"type": kind, "id": rid})
            except Exception:
                pass
        node.pending.pop(rid, None)
        if not fut.done():
            fut.cancel()
        try:
            await ws.close()
        except Exception:
            pass


async def handle_tcp_relay(ws) -> None:
    """WS <-> TCP byte pipe so nodes can reach LAN services through the hub.

    A node connects to /ws-relay?target=host:port&token=<node-secret>;
    binary WS messages are written to the TCP socket and TCP chunks are sent
    back as binary WS messages. Framing is irrelevant (both byte streams).
    """
    url = urllib.parse.urlsplit(ws.request.path)
    query = urllib.parse.parse_qs(url.query)
    if not node_authed(ws.request, query):
        await ws.close(4001, "bad token")
        return
    target = (query.get("target") or [""])[0]
    host, _, port_s = target.rpartition(":")
    try:
        port = int(port_s)
        if not host or not (0 < port < 65536) or port in BLOCKED_PORTS:
            raise ValueError
    except ValueError:
        await ws.close(4002, "bad target")
        return
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError as e:
        await ws.close(4003, f"connect failed: {e}")
        return

    async def ws_to_tcp() -> None:
        try:
            async for msg in ws:
                if isinstance(msg, str):
                    msg = msg.encode()
                writer.write(msg)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.write_eof()
            except Exception:
                pass

    async def tcp_to_ws() -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await ws.send(data)
        except Exception:
            pass
        finally:
            try:
                await ws.close()
            except Exception:
                pass

    tasks = [asyncio.create_task(ws_to_tcp()), asyncio.create_task(tcp_to_ws())]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 3)
        except (OSError, asyncio.TimeoutError):
            pass


async def handle_ws(ws) -> None:
    url = urllib.parse.urlsplit(ws.request.path)
    if url.path == "/ws-node":
        await handle_node_ws(ws)
        return
    if url.path == "/ws-upload":
        await handle_upload(ws)
        return
    if url.path == "/ws-relay":
        await handle_tcp_relay(ws)
        return
    query = urllib.parse.parse_qs(url.query)
    name = (query.get("session") or [""])[0]
    if not name:
        await ws.close(4000, "missing session")
        return
    nname, sname = split_node(name)
    if nname:
        remote = NODES.get(nname)
        if remote is None:
            await ws.close(4004, "node not connected")
            return
        await handle_node_attach(ws, remote, name, sname)
        return

    # Start the pty at the size this session's client last used, so the
    # first frame is already right; the client sends an explicit resize
    # right after connect to correct it if needed.
    cols, rows = _last_size.get(name, (220, 50))
    cid = id(ws)
    pid = fd = writer = None
    tasks = []
    loop = asyncio.get_running_loop()
    try:
        web_attach(name, cid, cols, rows)
        pid, fd = pty.fork()
        if pid == 0:  # child
            env = RUNTIME.tmux_environment()
            try:
                env["TERM"] = "xterm-256color"
                os.execvpe("tmux", RUNTIME.tmux_argv("attach-session", "-t", name), env)
            finally:
                os._exit(127)

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=256)
        set_winsize(fd, cols, rows)
        writer = PtyWriter(fd)

        def on_readable() -> None:
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                return
            except OSError:
                data = b""
            if data:
                try:
                    queue.put_nowait(data)
                except asyncio.QueueFull:
                    pass  # slow client: drop rather than block tmux
            else:
                loop.remove_reader(fd)
                _qput(queue, None)

        loop.add_reader(fd, on_readable)

        async def pty_to_ws() -> None:
            while True:
                item = await queue.get()
                if item is None:
                    break
                await ws.send(item)

        async def ws_to_pty() -> None:
            async for msg in ws:
                if isinstance(msg, str):
                    try:
                        ctl = json.loads(msg)
                    except ValueError:
                        continue
                    if ctl.get("type") == "resize":
                        cols = max(1, min(int(ctl.get("cols", 220)), 1000))
                        rows = max(1, min(int(ctl.get("rows", 50)), 1000))
                        _last_size[name] = (cols, rows)
                        set_winsize(fd, cols, rows)
                        web_resize(name, cid, cols, rows)
                else:
                    # Typing/scrolling in a client means that is the screen the
                    # user is actually looking at: it takes over size ownership.
                    st = _attach_state.get(name)
                    if st and st.get("owner") != cid:
                        st["owner"] = cid
                        _apply_size(name, st)
                    if not writer.write(msg):
                        await ws.send("\r\n[tmux-web] terminal input queue is full or unavailable; input was rejected.\r\n")

        tasks = [asyncio.create_task(pty_to_ws()), asyncio.create_task(ws_to_pty())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            web_detach(name, cid)
        except Exception as error:
            print(f"terminal detach cleanup failed: {type(error).__name__}", file=sys.stderr)
        if writer is not None:
            writer.close()
        if fd is not None:
            loop.remove_reader(fd)
            try:
                os.close(fd)
            except OSError:
                pass
        if pid is not None:
            try:
                os.kill(pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(asyncio.to_thread(os.waitpid, pid, 0), 5)
            except asyncio.TimeoutError:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.to_thread(os.waitpid, pid, 0)
                except ChildProcessError:
                    pass
            except ChildProcessError:
                pass


async def main() -> None:
    global _TOKENS
    os.makedirs(RUNTIME.state_dir, mode=0o700, exist_ok=True)
    _auth_state()
    _TOKENS = _load_tokens()
    node_secret()
    os.makedirs(PAGES_DIR, exist_ok=True)
    _cleanup_uploads()
    _cleanup_pages()
    asyncio.create_task(_page_sweeper())
    runner = web.AppRunner(create_app(sys.modules[__name__]))
    await runner.setup()
    try:
        await web.TCPSite(runner, HOST, PORT).start()
        print(f"tmux-web listening on http://{HOST}:{PORT}", flush=True)
        await asyncio.Future()
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except RuntimeError as exc:
        sys.exit(str(exc))
