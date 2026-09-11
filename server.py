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

from aiohttp import web
from http_frontend import create_app
from websockets.datastructures import Headers
from websockets.http11 import Response

HOST = os.environ.get("TMUX_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("TMUX_WEB_PORT", "59999"))


# ---------------------------------------------------------------------------
# Authentication: salted-hash password file + opaque bearer tokens in a cookie.
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_FILE = os.path.join(BASE_DIR, ".auth.json")
TOKEN_FILE = os.path.join(BASE_DIR, ".tokens.json")
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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(data, f)


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
        if k == "tmux_web_token" and _TOKENS.get(v, 0) > time.time():
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


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, interactive-widget=resizes-content">
<title>tmux web</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<style>
  :root {
    --bg: #0f1117; --panel: #161a23; --border: #262c3a;
    --fg: #d6dae3; --dim: #7a8394; --accent: #4f9cff; --danger: #e5534b;
  }
  * { box-sizing: border-box; margin: 0; }
  html, body { height: 100%; }
  body {
    font: 14px/1.5 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    background: var(--bg); color: var(--fg); display: flex; overflow: hidden;
  }
  /* sidebar */
  #side {
    width: 260px; min-width: 260px; background: var(--panel);
    border-right: 1px solid var(--border); display: flex; flex-direction: column;
  }
  #side header {
    padding: 14px 16px; font-weight: 600; font-size: 15px;
    border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px;
  }
  #newrow { display: flex; gap: 6px; padding: 10px 12px; border-bottom: 1px solid var(--border); }
  #newname {
    flex: 1; min-width: 0; background: var(--bg); color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px; padding: 6px 9px; outline: none;
  }
  #newname:focus { border-color: var(--accent); }
  button {
    background: var(--accent); color: #fff; border: 0; border-radius: 6px;
    padding: 6px 10px; cursor: pointer; font-size: 13px;
  }
  button.ghost { background: transparent; border: 1px solid var(--border); color: var(--dim); }
  button.ghost:hover { color: var(--fg); border-color: var(--dim); }
  #sessions { flex: 1; overflow-y: auto; padding: 6px; }
  .sess {
    display: flex; align-items: center; gap: 8px; padding: 9px 10px;
    border-radius: 6px; cursor: pointer; user-select: none;
  }
  .sess:hover { background: #1d2230; }
  .sess.active { background: #223050; }
  .sess .dot { width: 8px; height: 8px; border-radius: 50%; background: #3a4152; flex: none; }
  .sess.attached .dot { background: #3fb950; }
  .sess .name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sess .meta { color: var(--dim); font-size: 12px; flex: none; }
  .sess .kill { visibility: hidden; padding: 1px 7px; font-size: 12px; }
  .sess:hover .kill { visibility: visible; }
  @media (pointer: coarse) { .sess .kill { visibility: visible; } }
  #empty { color: var(--dim); text-align: center; margin-top: 40px; padding: 0 16px; }
  .nodehead {
    padding: 8px 10px 4px; font-size: 12px; color: var(--dim); font-weight: 600;
    border-top: 1px solid var(--border); margin-top: 6px;
  }
  /* child nodes panel */
  #nodeshead {
    padding: 8px 16px 4px; font-size: 12px; color: var(--dim);
    border-top: 1px solid var(--border); font-weight: 600; cursor: pointer;
  }
  #nodes { padding: 4px 6px; }
  .nodeitem {
    display: flex; align-items: center; gap: 8px; padding: 6px 10px;
    color: var(--dim); font-size: 13px;
  }
  .nodeitem .meta { margin-left: auto; font-size: 12px; }
  .nodeitem .nodesess { padding: 0 7px; font-size: 13px; line-height: 1.4; }
  .nodecmd {
    padding: 6px 10px; color: var(--accent); font-size: 12px; cursor: pointer;
    border-radius: 6px;
  }
  .nodecmd:hover { background: #1d2230; }
  /* published pages panel */
  #pageshead {
    padding: 8px 16px 4px; font-size: 12px; color: var(--dim);
    border-top: 1px solid var(--border); font-weight: 600;
  }
  #pages { max-height: 30%; overflow-y: auto; padding: 4px 6px; }
  .page {
    display: flex; align-items: center; gap: 8px; padding: 7px 10px;
    border-radius: 6px; cursor: pointer; user-select: none;
  }
  .page:hover { background: #1d2230; }
  .page .name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
  .page .meta { color: var(--dim); font-size: 11px; flex: none; }
  .page .del { visibility: hidden; padding: 1px 7px; font-size: 12px; }
  .page:hover .del { visibility: visible; }
  @media (pointer: coarse) { .page .del { visibility: visible; } }
  /* page viewer overlay */
  #pgmodal { position: fixed; inset: 0; background: var(--bg); z-index: 25; display: flex; }
  #pgcard { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  #pghead {
    display: flex; align-items: center; gap: 10px; padding: 8px 14px;
    background: var(--panel); border-bottom: 1px solid var(--border);
  }
  #pgtitle { flex: 1; font-weight: 600; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #pgframe { flex: 1; border: 0; background: var(--bg); }
  /* main */
  #main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  #topbar {
    height: 44px; display: flex; align-items: center; gap: 10px; padding: 0 14px;
    border-bottom: 1px solid var(--border); background: var(--panel);
  }
  #cur { font-weight: 600; }
  #status { font-size: 12px; color: var(--dim); }
  #status.ok { color: #3fb950; }
  #status.bad { color: var(--danger); }
  #portbar {
    position:relative;display:flex;align-items:center;flex:none;height:30px;margin:0;
    padding:0 3px 0 9px;background:#10141d;border:1px solid #2b3342;border-radius:7px;
    transition:border-color .15s,box-shadow .15s;
  }
  #portbar:focus-within { border-color:#547fb2;box-shadow:0 0 0 2px #4f9cff16; }
  #portbar .porticon { width:14px;height:14px;color:#758399;flex:none; }
  #portbar input {
    width:64px;min-width:0;padding:0 7px;border:0;outline:0;background:transparent;
    color:#d6dae3;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;appearance:textfield;
  }
  #portbar input::placeholder { color:#758399;font-family:inherit; }
  #portbar input::-webkit-inner-spin-button,#portbar input::-webkit-outer-spin-button { -webkit-appearance:none;margin:0; }
  #openport {
    display:flex;align-items:center;justify-content:center;gap:5px;height:24px;padding:0 7px;
    border:0;border-left:1px solid #2b3342;border-radius:0 4px 4px 0;
    background:transparent;color:#8fb9ee;font-size:12px;white-space:nowrap;
  }
  #openport:hover { background:#25364b;color:#c5dfff; }
  #openport svg { width:13px;height:13px; }
  #porterror:not(:empty) {
    position:absolute;right:0;top:36px;z-index:12;padding:7px 10px;border:1px solid #573239;
    border-radius:6px;background:#23171d;color:#ef9999;font-size:12px;white-space:nowrap;
    box-shadow:0 4px 16px #0004;
  }
  #cur { min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
  #topbar > button { flex:none; }
  #reconnect { display:flex;align-items:center;gap:5px; }
  #reconnect svg { width:14px;height:14px; }
  @media (max-width:700px) {
    #topbar { gap:8px;padding:0 10px;flex:none; }
    #cur { flex:1;font-size:12px; }
    #topspacer { display:none; }
    #status { width:6px;height:6px;flex:none;border-radius:50%;background:currentColor;font-size:0; }
    #portbar { padding-left:7px; }
    #portbar input { width:61px;font-size:16px; }
    #openport { width:26px;padding:0; }
    #openport span,#reconnect span { display:none; }
    #topbar > button { width:28px;height:28px;padding:0;justify-content:center; }
  }
  #termwrap { flex: 1; padding: 6px; min-height: 0; }
  #termwrap.dragover { outline: 3px dashed var(--accent); outline-offset: -6px; border-radius: 8px; }
  #term { height: 100%; }
  /* touch shortcut toolbar */
  #kbd {
    display: flex; gap: 6px; padding: 6px 8px; overflow-x: auto;
    background: var(--panel); border-top: 1px solid var(--border);
    -webkit-user-select: none; user-select: none;
  }
  #kbd button {
    flex: none; min-width: 44px; min-height: 40px; font-size: 14px;
    background: #232a3a; color: var(--fg); border: 1px solid var(--border);
  }
  #kbd button.on { background: var(--accent); border-color: var(--accent); }
  /* mobile: sidebar becomes an overlay */
  #menu { display: none; }
  @media (max-width: 700px) {
    #menu { display: inline-block; }
    #side {
      position: absolute; z-index: 10; height: 100%; left: 0; top: 0;
      box-shadow: 4px 0 16px rgba(0,0,0,.5);
      transition: transform .15s ease;
    }
    body.side-hidden #side { transform: translateX(-105%); }
  }
  #welcome {
    flex: 1; display: flex; align-items: center; justify-content: center;
    color: var(--dim); font-size: 15px; text-align: center; padding: 20px;
  }
  .hidden { display: none !important; }
  /* change-password modal */
  #pwmodal {
    position: fixed; inset: 0; background: rgba(0,0,0,.55); z-index: 20;
    display: flex; align-items: center; justify-content: center;
  }
  #pwcard {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 22px; width: 300px; display: flex; flex-direction: column; gap: 10px;
  }
  #pwcard h3 { font-size: 15px; }
  #pwcard input {
    background: var(--bg); color: var(--fg); border: 1px solid var(--border);
    border-radius: 6px; padding: 8px 10px; outline: none; font-size: 14px;
  }
  #pwcard input:focus { border-color: var(--accent); }
  #pwmsg { font-size: 13px; color: var(--danger); min-height: 16px; }
  /* host monitor modal */
  #monmodal {
    position: fixed; inset: 0; background: rgba(0,0,0,.6); z-index: 20;
    display: flex; align-items: center; justify-content: center; padding: 16px;
  }
  #moncard {
    background: var(--bg); border: 1px solid var(--border); border-radius: 12px;
    width: 100%; max-width: 980px; max-height: 100%; display: flex; flex-direction: column;
    overflow: hidden;
  }
  #monhead {
    display: flex; align-items: center; gap: 10px; padding: 12px 16px;
    border-bottom: 1px solid var(--border); background: var(--panel);
  }
  #monhead h3 { font-size: 15px; }
  #monsub { color: var(--dim); font-size: 12px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #mongrid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 12px; padding: 14px; overflow-y: auto;
  }
  .monpanel {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 12px 14px; min-width: 0;
  }
  .monpanel h4 { font-size: 13px; color: var(--dim); font-weight: 600; margin-bottom: 6px; }
  .monpanel .big { font-size: 22px; font-weight: 700; }
  .monpanel .sub { color: var(--dim); font-size: 12px; margin-top: 2px; }
  .monpanel canvas { width: 100% !important; }
  .chartbox { height: 110px; margin-top: 8px; }
  .chartbox.tall { height: 150px; }
  .bar { height: 8px; background: #232a3a; border-radius: 4px; overflow: hidden; margin: 6px 0 2px; }
  .bar > div { height: 100%; background: var(--accent); border-radius: 4px; transition: width .5s; }
  .gpu { margin-bottom: 10px; }
  .gpu .gpuname { font-size: 13px; display: flex; justify-content: space-between; gap: 8px; }
  .dim { color: var(--dim); font-size: 12px; }
  .drow { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .drow .dname { width: 90px; flex: none; font-size: 12px; color: var(--dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .drow .bar { flex: 1; margin: 0; }
  .drow .dval { width: 96px; flex: none; font-size: 12px; text-align: right; }
  /* token usage heatmap */
  .tokrow { display: flex; gap: 2px; align-items: center; margin-bottom: 3px; }
  .toklab { width: 72px; flex: none; font-size: 11px; color: var(--dim); }
  .tokcell { flex: 1; height: 14px; border-radius: 2px; min-width: 0; cursor: pointer; }
  .tokcell:hover { outline: 1px solid var(--dim); }
  .tokcell.sel { outline: 1px solid var(--fg); }
  .tokhead { margin-bottom: 2px; }
  .tokday { flex: 1; font-size: 9px; color: var(--dim); text-align: center; min-width: 0; }
  #tokdetail { margin-top: 10px; border-top: 1px solid var(--border); padding-top: 8px; }
  .tokdhead { display: flex; align-items: center; gap: 8px; font-size: 12px; margin-bottom: 6px; flex-wrap: wrap; }
  .tokdrow { display: flex; align-items: center; gap: 8px; font-size: 12px; padding: 3px 0; }
  .tokdtitle { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tokdmeta { color: var(--dim); flex: none; font-size: 11px; }
</style>
</head>
<body>
  <div id="side">
    <header>
      <span style="flex:1">&#9000;&#65039; tmux sessions</span>
      <button class="ghost" id="monbtn" title="host monitor">&#128202;</button>
      <button class="ghost" id="pwbtn" title="change password">&#128274;</button>
    </header>
    <div id="newrow">
      <input id="newname" placeholder="new session (node:name for a node)" spellcheck="false">
      <button id="newbtn">Create</button>
    </div>
    <div id="sessions"></div>
    <div id="nodeshead">&#128421; nodes</div>
    <div id="nodes"></div>
    <div id="pageshead" class="hidden">&#128196; pages</div>
    <div id="pages"></div>
  </div>
  <div id="main">
    <div id="topbar" class="hidden">
      <button class="ghost" id="menu">&#9776;</button>
      <span id="cur"></span>
      <span id="status"></span>
      <span id="topspacer" style="flex:1"></span>
      <form id="portbar" class="hidden" title="访问本机 HTTP 网页">
        <svg class="porticon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c4 5 4 13 0 18-4-5-4-13 0-18Z"/></svg>
        <input id="webport" type="number" min="1" max="65535" step="1" placeholder="端口" inputmode="numeric" required aria-label="HTTP 网页端口">
        <button type="submit" id="openport" title="打开网页" aria-label="打开网页"><span>打开</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 4h6v6m0-6L10 14m-1-9H5a1 1 0 0 0-1 1v13a1 1 0 0 0 1 1h13a1 1 0 0 0 1-1v-4"/></svg></button>
        <span id="porterror" role="status"></span>
      </form>
      <button class="ghost" id="upbtn" title="upload a file and type its path into the terminal">&#128228;</button>
      <input type="file" id="upfile" class="hidden">
      <button class="ghost" id="reconnect" title="Reconnect" aria-label="Reconnect"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 6a8 8 0 0 1 13 3l1 3M4 12l1 3a8 8 0 0 0 13 3"/></svg><span>Reconnect</span></button>
    </div>
    <div id="welcome">Select a session on the left,<br>or create a new one.</div>
    <div id="termwrap" class="hidden"><div id="term"></div></div>
    <div id="kbd" class="hidden">
      <button data-key="esc">Esc</button>
      <button data-key="tab">Tab</button>
      <button data-key="prefix">^B</button>
      <button id="ctrlkey">Ctrl</button>
      <button data-key="left">&#8592;</button>
      <button data-key="up">&#8593;</button>
      <button data-key="down">&#8595;</button>
      <button data-key="right">&#8594;</button>
      <button id="scrup" title="scroll up">&#8648;</button>
      <button id="scrdn" title="scroll down">&#8650;</button>
      <button data-key="home">Home</button>
      <button data-key="end">End</button>
      <button data-key="pgup">PgUp</button>
      <button data-key="pgdn">PgDn</button>
      <button id="ime">&#9000;</button>
    </div>
  </div>

  <div id="pwmodal" class="hidden">
    <div id="pwcard">
      <h3>Change password</h3>
      <input id="pwold" type="password" placeholder="current password">
      <input id="pwnew" type="password" placeholder="new password (6-128 chars)">
      <input id="pwnew2" type="password" placeholder="repeat new password">
      <div id="pwmsg"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button class="ghost" id="pwcancel">Cancel</button>
        <button id="pwsave">Save</button>
      </div>
    </div>
  </div>

  <div id="monmodal" class="hidden">
    <div id="moncard">
      <div id="monhead">
        <h3>&#128202; Host monitor</h3>
        <span id="monsub"></span>
        <button class="ghost" id="monclose">&#10005;</button>
      </div>
      <div id="mongrid">
        <div class="monpanel">
          <h4>CPU</h4>
          <div class="big" id="cpupct">–</div>
          <div class="sub" id="cpuinfo"></div>
          <div class="chartbox"><canvas id="cpuchart"></canvas></div>
        </div>
        <div class="monpanel">
          <h4>Memory</h4>
          <div class="big" id="mempct">–</div>
          <div class="sub" id="meminfo"></div>
          <div class="chartbox"><canvas id="memchart"></canvas></div>
        </div>
        <div class="monpanel">
          <h4>Network</h4>
          <div class="sub" id="netinfo"></div>
          <div class="chartbox tall"><canvas id="netchart"></canvas></div>
        </div>
        <div class="monpanel">
          <h4>GPU</h4>
          <div id="gpulist"></div>
        </div>
        <div class="monpanel">
          <h4>Disk</h4>
          <div id="disklist"></div>
        </div>
        <div class="monpanel" id="tokpanel">
          <h4 style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Tokens · last 30 days
            <select id="toksource" aria-label="Token 来源" style="background:var(--bg);color:inherit;border:1px solid #444;border-radius:5px;padding:4px 8px">
              <option value="all">总计 (Kimi + Codex)</option>
              <option value="kimi">Kimi</option><option value="codex">Codex</option>
            </select>
          </h4>
          <div id="tokgrid"></div>
          <div class="sub" id="toksum"></div>
          <div id="tokdetail" class="hidden"></div>
        </div>
      </div>
    </div>
  </div>

  <div id="pgmodal" class="hidden">
    <div id="pgcard">
      <div id="pghead">
        <span id="pgtitle"></span>
        <button class="ghost" id="pgclose">&#10005;</button>
      </div>
      <iframe id="pgframe" sandbox="allow-scripts"></iframe>
    </div>
  </div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<script>
const $ = id => document.getElementById(id);
let current = null, ws = null, term = null, fit = null;
let sessCache = [], currentNode = '';

function esc(s){ const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function sessEl(s) {
  const el = document.createElement('div');
  el.className = 'sess' + (s.attached ? ' attached' : '') + (s.name === current ? ' active' : '');
  el.innerHTML = `<span class="dot"></span><span class="name">${esc(s.name)}</span>` +
                 `<span class="meta">${s.windows}w</span>` +
                 `<button class="ghost kill" title="kill session">&#10005;</button>`;
  el.onclick = () => attach(s.name);
  el.querySelector('.kill').onclick = async ev => {
    ev.stopPropagation();
    if (!confirm(`Kill session "${s.name}"?`)) return;
    await fetch('/api/kill?name=' + encodeURIComponent(s.name));
    if (current === s.name) disconnect();
    refresh();
  };
  return el;
}

async function refreshNodes() {
  let info = null;
  try {
    const r = await fetch('/api/nodes');
    if (r.ok) info = await r.json();
  } catch(e) {}
  const box = $('nodes');
  if (!info) { box.innerHTML = ''; return; }
  box.innerHTML = info.nodes.map(n =>
    `<div class="nodeitem">&#128421; ${esc(n.name)}<span class="meta">${n.encrypted ? '🔒 ' : ''}${n.sessions} sess</span>` +
    `<button class="ghost nodesess" data-node="${esc(n.name)}" title="new session on ${esc(n.name)}">+</button></div>`
  ).join('') + '<div class="nodecmd nodejoin" title="copy a command to download and connect an encrypted node">+ add a node</div>';
  box.querySelectorAll('.nodesess').forEach(b => b.onclick = async () => {
    const name = prompt('Session name on ' + b.dataset.node + ':');
    if (!name || !name.trim()) return;
    const full = b.dataset.node + ':' + name.trim();
    const r = await fetch('/api/new?name=' + encodeURIComponent(full));
    if (r.ok) { await refresh(); attach(full); }
    else alert(await r.text());
  });
  box.querySelector('.nodejoin').onclick = () => {
    const bootstrap = 'import hashlib,os,pathlib,sys,tempfile,urllib.request; ' +
      'data=urllib.request.urlopen(sys.argv[1],timeout=30).read(); ' +
      'digest=hashlib.sha256(data).hexdigest(); ' +
      'digest==sys.argv[2] or sys.exit("node download integrity check failed"); ' +
      'folder=pathlib.Path(tempfile.mkdtemp(prefix="tmux-web-node-")); ' +
      'script=folder/"node.py"; script.write_bytes(data); ' +
      'os.environ["TMUX_WEB_NODE_TOKEN"]=sys.argv[4]; ' +
      'os.execv(sys.executable,[sys.executable,"-S",str(script),"--server",sys.argv[3]]+sys.argv[5:])';
    const base = location.hostname + ':' + info.port;
    const endpoint = 'ws://' + base + '/ws-node';
    const cmd = 'python3 -c ' + shellQuote(bootstrap) + ' ' + shellQuote('http://' + base + '/node.py') +
      ' ' + shellQuote(info.node_script_sha256) + ' ' + shellQuote(endpoint) + ' ' + shellQuote(info.secret);
    copyText(cmd);
    setStatus('connection command copied — run it on the node; encryption is automatic', 'ok');
  };
}

async function refresh() {
  refreshPages();
  refreshNodes();
  let list = [];
  try {
    const r = await fetch('/api/sessions');
    if (r.status === 401) { location.reload(); return; }
    list = await r.json();
  } catch(e) {}
  sessCache = list;
  const box = $('sessions');
  if (!list.length) { box.innerHTML = '<div id="empty">No tmux sessions.<br>Create one above.</div>'; return; }
  box.innerHTML = '';
  const byNode = {};
  for (const s of list) {
    if (!s.node) { box.appendChild(sessEl(s)); continue; }
    (byNode[s.node] = byNode[s.node] || []).push(s);
  }
  for (const n of Object.keys(byNode).sort()) {
    const h = document.createElement('div');
    h.className = 'nodehead';
    h.textContent = '\u{1F5A5} ' + n;
    box.appendChild(h);
    byNode[n].forEach(s => box.appendChild(sessEl(s)));
  }
}

function setStatus(txt, cls) { const st = $('status'); st.textContent = txt; st.className = cls || ''; }

/* ---- touch shortcut toolbar ---- */
const IS_TOUCH = matchMedia('(pointer: coarse)').matches || 'ontouchstart' in window;
let ctrlOn = false;
const KEYS = {
  esc:    ['\x1b'],      tab:   ['\t'],      prefix: ['\x02'],
  left:   ['\x1b[D', '\x1b[1;5D'], up:   ['\x1b[A', '\x1b[1;5A'],
  down:   ['\x1b[B', '\x1b[1;5B'], right:['\x1b[C', '\x1b[1;5C'],
  home:   ['\x1b[H'],    end:   ['\x1b[F'],
  pgup:   ['\x1b[5~'],   pgdn:  ['\x1b[6~'],
};
function sendRaw(s) { if (ws && ws.readyState === 1) ws.send(new TextEncoder().encode(s)); }

/* Translate touch drags into SGR wheel events so tmux scrolls. */
function enableTouchScroll() {
  const el = $('term');
  let lastY = null, acc = 0;
  el.addEventListener('touchstart', e => {
    lastY = e.touches[0].clientY; acc = 0;
  }, {passive: true});
  el.addEventListener('touchmove', e => {
    if (lastY === null || !term) return;
    const t = e.touches[0];
    acc += lastY - t.clientY;          // >0: finger moved up => scroll down
    lastY = t.clientY;
    const lineH = el.clientHeight / (term.rows || 24);
    const steps = Math.trunc(acc / lineH);
    if (!steps) return;
    acc -= steps * lineH;
    e.preventDefault();                // stop page/xterm native handling
    const col = Math.max(1, Math.round(t.clientX / el.clientWidth * term.cols));
    const row = Math.max(1, Math.round(t.clientY / el.clientHeight * term.rows));
    const btn = steps > 0 ? 65 : 64;   // 65 = wheel down, 64 = wheel up
    for (let i = 0; i < Math.abs(steps); i++) sendRaw(`\x1b[<${btn};${col};${row}M`);
  }, {passive: false});
  el.addEventListener('touchend', () => { lastY = null; });
}
function setCtrl(on) {
  ctrlOn = on;
  $('ctrlkey').classList.toggle('on', on);
}
document.querySelectorAll('#kbd [data-key]').forEach(btn => {
  btn.addEventListener('click', () => {
    const seqs = KEYS[btn.dataset.key];
    sendRaw(ctrlOn && seqs[1] ? seqs[1] : seqs[0]);
    if (ctrlOn) setCtrl(false);
    term && term.focus();
  });
});
$('ctrlkey').addEventListener('click', () => { setCtrl(!ctrlOn); term && term.focus(); });

/* wheel buttons: tap = 3 lines, hold = continuous scroll. Same SGR wheel
   sequences as the touch-drag translation, but deterministic. */
function sendWheel(lines, up) {
  if (!term) return;
  const col = Math.max(1, Math.floor(term.cols / 2));
  const row = Math.max(1, Math.floor(term.rows / 2));
  const btn = up ? 64 : 65;
  for (let i = 0; i < lines; i++) sendRaw(`\x1b[<${btn};${col};${row}M`);
}
[['scrup', true], ['scrdn', false]].forEach(([id, up]) => {
  const b = $(id);
  let timer = null;
  const start = e => {
    e.preventDefault();
    sendWheel(3, up);
    timer = setInterval(() => sendWheel(3, up), 120);
  };
  const stop = () => { clearInterval(timer); timer = null; };
  b.addEventListener('pointerdown', start);
  b.addEventListener('pointerup', stop);
  b.addEventListener('pointercancel', stop);
  b.addEventListener('pointerleave', stop);
});
$('ime').addEventListener('click', () => { term && term.focus(); });
$('menu').addEventListener('click', () => document.body.classList.toggle('side-hidden'));

/* ---- clickable file paths in terminal output -> download ---- */
function nodeParam() { return currentNode ? '&node=' + encodeURIComponent(currentNode) : ''; }
async function downloadPath(p) {
  setStatus('checking ' + p + '…');
  try {
    const r = await fetch('/api/download?check=1&path=' + encodeURIComponent(p) + nodeParam());
    if (r.status === 401) { location.reload(); return; }
    if (!r.ok) { setStatus('not a downloadable file: ' + p, 'bad'); return; }
    const a = document.createElement('a');
    a.href = '/api/download?path=' + encodeURIComponent(p) + nodeParam();
    document.body.appendChild(a);
    a.click();
    a.remove();
    setStatus('downloading ' + p, 'ok');
  } catch (e) {
    setStatus('download failed: ' + p, 'bad');
  }
}
/* Server-side disambiguation for paths that wrap across lines: when a
   candidate match spans a line boundary, junk from the next line may have
   been glued on (e.g. the following shell prompt). The server trims the
   candidate to the longest prefix that is an existing file. */
const resolveCache = new Map();
async function resolvePath(p) {
  if (resolveCache.has(p)) return resolveCache.get(p);
  let r = null;
  try {
    const resp = await fetch('/api/resolve-path?path=' + encodeURIComponent(p) + nodeParam());
    if (resp.ok) r = (await resp.json()).path || null;
  } catch (e) { /* offline: no link */ }
  if (resolveCache.size > 500) resolveCache.clear();
  resolveCache.set(p, r);
  return r;
}
function setupPathLinks() {
  term.registerLinkProvider({
    provideLinks(y, cb) {
      try {
        const buf = term.buffer.active;
        const K = 12;          // how many lines up/down a path may wrap
        const yLine = y - 1;   // absolute buffer line
        // Read one line as trimmed text plus a per-char cell-x map. Wide
        // chars (CJK) occupy 2 cells, so string offsets and cell offsets
        // diverge — the map keeps link ranges aligned.
        const readLine = ly => {
          const ln = buf.getLine(ly);
          if (!ln) return null;
          let txt = '';
          const cells = [];
          for (let i = 0; i < ln.length; i++) {
            const cell = ln.getCell(i);
            if (!cell) break;
            const ch = cell.getChars();
            if (!ch || cell.getWidth() === 0) continue;  // blank / wide-char spacer
            for (let k = 0; k < ch.length; k++) { txt += ch[k]; cells.push(i); }
          }
          let a = 0, b = txt.length;
          while (a < b && /\s/.test(txt[a])) a++;
          while (b > a && /\s/.test(txt[b - 1])) b--;
          return { txt: txt.slice(a, b), cells: cells.slice(a, b) };
        };
        // Join the block of non-blank lines around yLine, so paths wrapped
        // onto continuation lines (by the app or by the pty) still match.
        const center = readLine(yLine);
        if (!center) { cb([]); return; }
        const lines = [center];
        let ly0 = yLine;
        for (let ly = yLine - 1; ly >= yLine - K; ly--) {
          const r = readLine(ly);
          if (!r || !r.txt) break;
          lines.unshift(r); ly0 = ly;
        }
        for (let ly = yLine + 1; ly <= yLine + K; ly++) {
          const r = readLine(ly);
          if (!r || !r.txt) break;
          lines.push(r);
        }
        let text = '';
        const cellOf = [];
        const boundary = new Set();  // text offsets where a new line begins
        lines.forEach((r, idx) => {
          if (idx > 0) boundary.add(text.length);
          const ly = ly0 + idx;
          for (let k = 0; k < r.txt.length; k++) cellOf.push({ ly, x: r.cells[k] });
          text += r.txt;
        });
        const makeLink = (start, p) => {
          const s = cellOf[start], e = cellOf[start + p.length - 1];
          if (!s || !e) return null;
          return {
            range: {
              start: { x: s.x + 1, y: s.ly + 1 },
              end: { x: e.x + 1, y: e.ly + 1 },
            },
            text: p,
            activate(_ev, t) { downloadPath(t); },
          };
        };
        const re = /(~?\/(?:[^\s'"`|:;&<>(){}\[\]\\\/]+\/)*[^\s'"`|:;&<>(){}\[\]\\\/]+)/g;
        const sameLine = [];
        const cross = [];
        let m;
        while ((m = re.exec(text))) {
          const start = m.index;
          // A path must start at a delimiter or a line boundary, not in the
          // middle of a word (matches the old single-line behavior).
          if (start > 0 && !boundary.has(start) && /[\w\/.\-~]/.test(text[start - 1])) continue;
          let p = m[1];
          // A continuation line starting with / or ~/ is a NEW path, not a
          // wrap of this one: stop the match at the boundary so the next
          // path is scanned separately.
          for (const b of boundary) {
            if (b > start && b < start + p.length &&
                (text[b] === '/' || (text[b] === '~' && text[b + 1] === '/'))) {
              p = text.slice(start, b);
              re.lastIndex = b;
              break;
            }
          }
          p = p.replace(/[.,;:'"\"'，。；：、）】」]+$/, '');
          if (p.length < 3) continue;
          const s = cellOf[start], e = cellOf[start + p.length - 1];
          if (!s || !e) continue;
          if (s.ly === e.ly) {
            if (s.ly === yLine) sameLine.push(makeLink(start, p));
          } else {
            cross.push({ start, p });
          }
        }
        const finish = resolved => {
          const links = sameLine.filter(Boolean);
          cross.forEach((c, i) => {
            const p = resolved[i];
            if (!p) return;
            const s = cellOf[c.start], e = cellOf[c.start + p.length - 1];
            if (!s || !e) return;
            if (yLine < s.ly || yLine > e.ly) return;
            links.push(makeLink(c.start, p));
          });
          cb(links);
        };
        if (!cross.length) { finish([]); return; }
        Promise.all(cross.map(c => resolvePath(c.p))).then(finish, () => finish([]));
      } catch (e) { cb([]); }
    },
  });
}

/* Strip mouse-reporting mode sets (1000/1002/1003 + format modes) from the
   pty stream: xterm then never enters reporting mode, so clicks are NOT
   forwarded to tmux and drags fall back to native text selection. Scrolling
   still works because the custom wheel handler below sends SGR wheel
   sequences itself. */
const MOUSE_MODE_RE = /\x1b\[\?(?:1000|1002|1003|1005|1006|1015|1016)[hl]/g;
const TAIL_RE = /\x1b(?:\[\??[\d;]*)$/;  // possible partial CSI at chunk end
function makeMouseFilter() {
  let tail = '';
  return chunk => {  // chunk: Uint8Array -> Uint8Array
    // bytes -> latin1 string, 1:1 (TextDecoder('iso-8859-1') would map to
    // windows-1252 and corrupt bytes 0x80-0x9F, so do it manually)
    let s = tail;
    tail = '';
    for (let i = 0; i < chunk.length; i++) s += String.fromCharCode(chunk[i]);
    const m = s.match(TAIL_RE);
    if (m) { tail = m[0]; s = s.slice(0, -m[0].length); }
    s = s.replace(MOUSE_MODE_RE, '');
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  };
}

/* clipboard helpers: the Clipboard API needs a secure context (https), so on
   plain http we fall back to execCommand('copy') / a paste prompt. */
function copyText(t) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(t).catch(() => fallbackCopy(t));
  } else fallbackCopy(t);
}
function fallbackCopy(t) {
  const ta = document.createElement('textarea');
  ta.value = t;
  ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) {}
  ta.remove();
}
function pasteClipboard() {
  if (navigator.clipboard && navigator.clipboard.readText) {
    navigator.clipboard.readText()
      .then(t => { if (t) sendRaw(t); })
      .catch(() => pastePrompt());
  } else pastePrompt();
}
function pastePrompt() {
  const t = prompt('Paste text to send to the terminal:');
  if (t) sendRaw(t);
}

function ensureTerm() {
  if (term) return;
  term = new Terminal({
    fontFamily: '"JetBrains Mono", Menlo, Consolas, monospace',
    fontSize: 14, cursorBlink: true, scrollback: 5000,
    theme: { background: '#0f1117' }
  });
  fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($('term'));
  setupPathLinks();
  if (IS_TOUCH) enableTouchScroll();
  // Wheel scroll: reporting mode is stripped from the stream, so send the
  // SGR wheel sequences to tmux ourselves instead of scrolling xterm's
  // scrollback. Capture phase + stopPropagation keeps xterm's own viewport
  // wheel handler from firing.
  let wheelAcc = 0;
  $('term').addEventListener('wheel', ev => {
    if (!ws || ws.readyState !== 1) return;
    ev.preventDefault();
    ev.stopPropagation();
    const px = ev.deltaMode === 1 ? ev.deltaY * 40 : ev.deltaMode === 2 ? ev.deltaY * 400 : ev.deltaY;
    wheelAcc += px;
    const lines = Math.trunc(wheelAcc / 40);
    if (!lines) return;
    wheelAcc -= lines * 40;
    const el = $('term');
    const col = Math.max(1, Math.round(ev.offsetX / el.clientWidth * term.cols));
    const row = Math.max(1, Math.round(ev.offsetY / el.clientHeight * term.rows));
    const btn = lines > 0 ? 65 : 64;
    for (let i = 0; i < Math.min(Math.abs(lines), 10); i++) sendRaw(`\x1b[<${btn};${col};${row}M`);
  }, { passive: false, capture: true });
  // Drag-select copies automatically (debounced so it fires when the drag settles).
  let copyTimer = null;
  term.onSelectionChange(() => {
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => {
      const s = term.getSelection();
      if (s) copyText(s);
    }, 400);
  });
  // Right-click pastes. Touch long-press (contextmenu without a mouse) is
  // left alone so it can still drive selection.
  $('term').addEventListener('contextmenu', ev => {
    if ('pointerType' in ev && ev.pointerType && ev.pointerType !== 'mouse') return;
    ev.preventDefault();
    pasteClipboard();
  });
  term.onData(d => {
    if (ctrlOn) {  // sticky Ctrl: turn the next printable char into a control char
      setCtrl(false);
      if (d.length === 1) {
        const ch = d.toUpperCase().charCodeAt(0);
        if (ch >= 64 && ch <= 95) { sendRaw(String.fromCharCode(ch & 0x1f)); return; }
        if (d === '?') { sendRaw('\x7f'); return; }
      }
    }
    sendRaw(d);
  });
  term.onResize(({cols, rows}) => {
    if (ws && ws.readyState === 1) ws.send(JSON.stringify({type:'resize', cols, rows}));
  });
  // Re-fit on any layout change: window resize, sidebar toggle, mobile
  // keyboard open/close, orientation change. Debounced because fit() is
  // not cheap and ResizeObserver can fire in bursts.
  let fitTimer = null;
  const scheduleFit = () => {
    clearTimeout(fitTimer);
    fitTimer = setTimeout(() => {
      if (!$('termwrap').classList.contains('hidden')) { try { fit.fit(); } catch(e){} }
    }, 80);
  };
  new ResizeObserver(scheduleFit).observe($('termwrap'));
  window.addEventListener('resize', scheduleFit);
  // Font metrics may shift once webfonts finish loading: measure again.
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(scheduleFit);
}

// The server resets the pty to a default size on every attach, and
// term.onResize does not fire when the size is unchanged — so always
// tell the server our actual size explicitly once connected.
function sendSize() {
  if (ws && ws.readyState === 1 && term)
    ws.send(JSON.stringify({type:'resize', cols: term.cols, rows: term.rows}));
}

function disconnect() {
  cancelRetry();
  retryCount = 0;
  if (ws) { ws.onclose = null; ws.close(); ws = null; }
  current = null;
  currentNode = '';
  setCtrl(false);
  $('topbar').classList.add('hidden');
  $('portbar').classList.add('hidden');
  $('termwrap').classList.add('hidden');
  $('kbd').classList.add('hidden');
  $('welcome').classList.remove('hidden');
  document.body.classList.remove('side-hidden');
}

/* ---- auto-reconnect with exponential backoff ---- */
let retryTimer = null, retryCount = 0;
function cancelRetry() { clearTimeout(retryTimer); retryTimer = null; }
function scheduleReconnect() {
  if (!current || retryTimer) return;
  const delay = Math.min(1000 * 2 ** retryCount, 10000);
  retryCount++;
  setStatus('connection lost — reconnecting in ' + Math.round(delay / 1000) + 's…', 'bad');
  retryTimer = setTimeout(async () => {
    retryTimer = null;
    if (!current) return;
    try {
      const r = await fetch('/api/sessions');
      if (r.status === 401) { location.reload(); return; }  // login expired
      if (r.ok && !(await r.json()).some(s => s.name === current)) {
        retryCount = 0;
        setStatus('session ended', 'bad');
        refresh();
        return;
      }
    } catch (e) { /* server unreachable: attach anyway and retry on close */ }
    attach(current);
  }, delay);
}

function attach(name) {
  cancelRetry();
  if (ws) { ws.onclose = null; ws.close(); }
  current = name;
  currentNode = (sessCache.find(s => s.name === name) || {}).node || '';
  ensureTerm();
  $('welcome').classList.add('hidden');
  $('topbar').classList.remove('hidden');
  $('portbar').classList.remove('hidden');
  $('termwrap').classList.remove('hidden');
  if (IS_TOUCH) $('kbd').classList.remove('hidden');
  if (matchMedia('(max-width: 700px)').matches) document.body.classList.add('side-hidden');
  $('cur').textContent = name;
  setStatus('connecting…');
  term.reset();

  ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') +
                     location.host + '/ws?session=' + encodeURIComponent(name));
  ws.binaryType = 'arraybuffer';
  const mouseFilter = makeMouseFilter();
  ws.onopen = () => {
    retryCount = 0;
    setStatus('connected', 'ok');
    fit.fit();
    sendSize();
    // Layout/fonts may still be settling right after open; measure again
    // shortly after so the session does not get stuck at a wrong size.
    setTimeout(() => { try { fit.fit(); } catch(e){} sendSize(); }, 300);
    term.focus();
  };
  ws.onmessage = ev => term.write(typeof ev.data === 'string'
    ? ev.data.replace(MOUSE_MODE_RE, '')
    : mouseFilter(new Uint8Array(ev.data)));
  ws.onclose = () => { setStatus('disconnected', 'bad'); scheduleReconnect(); };
  ws.onerror = () => { setStatus('error', 'bad'); };
  refresh();
}

$('reconnect').onclick = () => current && attach(current);

$('portbar').onsubmit = event => {
  event.preventDefault();
  const value = $('webport').value.trim(), port = Number(value);
  if (!/^[0-9]+$/.test(value) || !Number.isInteger(port) || port < 1 || port > 65535) {
    $('porterror').textContent = '请输入 1–65535 之间的端口号';
    return;
  }
  $('porterror').textContent = '';
  window.open('/port/' + port + '/', '_blank', 'noopener,noreferrer');
};
$('webport').oninput = () => { $('porterror').textContent = ''; };


/* ---- file upload: send to /ws-upload, then type the temp path ---- */
function shellQuote(p) {
  return /[^A-Za-z0-9_\-.,:\/=+~]/.test(p) ? "'" + p.replace(/'/g, "'\\''") + "'" : p;
}
$('upbtn').onclick = () => {
  if (!ws || ws.readyState !== 1) { alert('Attach to a session first.'); return; }
  $('upfile').click();
};
$('upfile').addEventListener('change', e => {
  const f = e.target.files[0];
  e.target.value = '';
  if (f) uploadFile(f);
});
async function uploadFile(f) {
  const btn = $('upbtn');
  btn.disabled = true;
  try {
    const u = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') +
                            location.host + '/ws-upload' +
                            (currentNode ? '?node=' + encodeURIComponent(currentNode) : ''));
    const path = await new Promise((resolve, reject) => {
      let settled = false;
      const ok = v => { if (!settled) { settled = true; resolve(v); } };
      const bad = v => { if (!settled) { settled = true; reject(v instanceof Error ? v : new Error(v)); } };
      u.onopen = async () => {
        try {
          u.send(JSON.stringify({ name: f.name, size: f.size }));
          const CHUNK = 262144;
          for (let off = 0; off < f.size; off += CHUNK) {
            while (u.bufferedAmount > 1 << 20) await new Promise(r => setTimeout(r, 50));
            u.send(f.slice(off, off + CHUNK));
            btn.textContent = Math.min(99, Math.round((off + CHUNK) / f.size * 100)) + '%';
          }
        } catch (err) { bad(err); }
      };
      u.onmessage = ev => {
        try {
          const m = JSON.parse(ev.data);
          m.ok ? ok(m.path) : bad(m.error || 'upload failed');
        } catch (err) { bad(err); }
      };
      u.onerror = () => bad('upload connection failed');
      u.onclose = () => bad('upload connection closed');
    });
    sendRaw(shellQuote(path));
    setStatus('uploaded: ' + f.name, 'ok');
  } catch (err) {
    alert('Upload failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '\u{1F4E4}';
  }
}
/* drag & drop a file onto the terminal -> same upload flow */
{
  const tw = $('termwrap');
  let dragDepth = 0;
  const hasFiles = e => e.dataTransfer && [...(e.dataTransfer.types || [])].includes('Files');
  tw.addEventListener('dragenter', e => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    dragDepth++;
    tw.classList.add('dragover');
  });
  tw.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
  tw.addEventListener('dragleave', e => {
    if (!hasFiles(e)) return;
    if (--dragDepth <= 0) { dragDepth = 0; tw.classList.remove('dragover'); }
  });
  tw.addEventListener('drop', async e => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    dragDepth = 0;
    tw.classList.remove('dragover');
    if (!ws || ws.readyState !== 1) { alert('Attach to a session first.'); return; }
    const files = [...e.dataTransfer.files];
    for (const f of files) {
      await uploadFile(f);
      if (f !== files[files.length - 1]) sendRaw(' ');
    }
  });
  /* never let a missed drop navigate the page away */
  window.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener('drop', e => { if (hasFiles(e)) e.preventDefault(); });
}
$('newbtn').onclick = async () => {
  const name = $('newname').value.trim();
  if (!name) return;
  const r = await fetch('/api/new?name=' + encodeURIComponent(name));
  if (r.ok) { $('newname').value = ''; await refresh(); attach(name); }
  else alert(await r.text());
};
$('newname').addEventListener('keydown', e => { if (e.key === 'Enter') $('newbtn').click(); });

/* change-password modal */
$('pwbtn').onclick = () => {
  $('pwold').value = $('pwnew').value = $('pwnew2').value = '';
  $('pwmsg').textContent = '';
  $('pwmodal').classList.remove('hidden');
  $('pwold').focus();
};
$('pwcancel').onclick = () => $('pwmodal').classList.add('hidden');
$('pwsave').onclick = async () => {
  const oldpw = $('pwold').value, newpw = $('pwnew').value;
  const msg = $('pwmsg');
  if (newpw !== $('pwnew2').value) { msg.textContent = 'new passwords do not match'; return; }
  const r = await fetch('/api/passwd?old=' + encodeURIComponent(oldpw) +
                        '&new=' + encodeURIComponent(newpw));
  if (r.ok) { $('pwmodal').classList.add('hidden'); alert('Password changed.'); }
  else msg.textContent = (await r.text()).trim();
};

/* ---- host monitor ---- */
const HIST = 60;  // 60 samples x 2s = 2 minutes of history
const hist = { labels: [], cpu: [], mem: [], rx: [], tx: [] };
let monTimer = null, tokTimer = null, charts = null;

function fmtB(b) {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(b >= 100 ? 0 : b >= 10 ? 1 : 2) + ' ' + u[i];
}
function fmtUp(s) {
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return (d ? d + 'd ' : '') + (d || h ? h + 'h ' : '') + m + 'm';
}
function pushHist(cpu, mem, rx, tx) {
  hist.labels.push(new Date().toLocaleTimeString());
  hist.cpu.push(cpu); hist.mem.push(mem); hist.rx.push(rx); hist.tx.push(tx);
  if (hist.labels.length > HIST) {
    hist.labels.shift(); hist.cpu.shift(); hist.mem.shift(); hist.rx.shift(); hist.tx.shift();
  }
}
function makeCharts() {
  const grid = { color: 'rgba(255,255,255,.06)' };
  const tick = { color: '#7a8394', font: { size: 10 } };
  const base = {
    type: 'line',
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      elements: { point: { radius: 0 } },
      scales: { x: { ticks: { ...tick, maxTicksLimit: 6 }, grid },
                y: { min: 0, ticks: tick, grid } },
      plugins: { legend: { display: false } },
    },
  };
  const line = (label, data, color) => ({
    label, data, borderColor: color, backgroundColor: color + '33',
    fill: true, tension: .3, borderWidth: 1.5,
  });
  const cpuOpts = JSON.parse(JSON.stringify(base.options)); cpuOpts.scales.y.max = 100;
  const memOpts = JSON.parse(JSON.stringify(base.options)); memOpts.scales.y.max = 100;
  const netOpts = JSON.parse(JSON.stringify(base.options));
  netOpts.plugins.legend = { display: true, labels: { color: '#d6dae3', boxWidth: 12, font: { size: 11 } } };
  netOpts.scales.y.ticks.callback = v => fmtB(v) + '/s';
  charts = {
    cpu: new Chart($('cpuchart'), { type: 'line', data: { labels: hist.labels, datasets: [line('CPU %', hist.cpu, '#4f9cff')] }, options: cpuOpts }),
    mem: new Chart($('memchart'), { type: 'line', data: { labels: hist.labels, datasets: [line('Mem %', hist.mem, '#e5534b')] }, options: memOpts }),
    net: new Chart($('netchart'), { type: 'line', data: { labels: hist.labels, datasets: [line('RX', hist.rx, '#3fb950'), line('TX', hist.tx, '#4f9cff')] }, options: netOpts }),
  };
}
function renderGpus(gpus) {
  const box = $('gpulist');
  if (!gpus.length) { box.innerHTML = '<div class="dim">No NVIDIA GPU detected</div>'; return; }
  box.innerHTML = gpus.map(g => `
    <div class="gpu">
      <div class="gpuname"><span>${esc(g.index + '. ' + g.name)}</span><span class="dim">${g.temp}&deg;C${g.power != null ? ' · ' + g.power.toFixed(0) + 'W' : ''}</span></div>
      <div class="bar"><div style="width:${g.util}%"></div></div>
      <div class="dim">util ${g.util}% &middot; mem ${fmtB(g.mem_used)} / ${fmtB(g.mem_total)}</div>
    </div>`).join('');
}
function renderDisks(disks) {
  const box = $('disklist');
  if (!disks.length) { box.innerHTML = '<div class="dim">No disks found</div>'; return; }
  box.innerHTML = disks.map(d => {
    const pct = d.total ? 100 * d.used / d.total : 0;
    const color = pct > 90 ? 'var(--danger)' : pct > 75 ? '#d29922' : 'var(--accent)';
    return `<div class="drow" title="${esc(d.mount)}">
      <span class="dname">${esc(d.mount)}</span>
      <span class="bar"><span style="display:block;height:100%;width:${pct.toFixed(1)}%;background:${color}"></span></span>
      <span class="dval">${fmtB(d.used)} / ${fmtB(d.total)}</span>
    </div>`;
  }).join('');
}
async function monPoll() {
  let s;
  try {
    const r = await fetch('/api/stats');
    if (r.status === 401) { location.reload(); return; }
    s = await r.json();
  } catch (e) { return; }
  $('monsub').textContent = `${s.host} · up ${fmtUp(s.uptime)}`;
  $('cpupct').textContent = s.cpu.pct.toFixed(1) + '%';
  $('cpuinfo').textContent = `${s.cpu.cores} cores · load ${s.cpu.load.map(x => x.toFixed(2)).join(' ')}`;
  const memPct = s.mem.total ? 100 * s.mem.used / s.mem.total : 0;
  $('mempct').textContent = memPct.toFixed(1) + '%';
  $('meminfo').textContent = `${fmtB(s.mem.used)} / ${fmtB(s.mem.total)}` +
    (s.mem.swap_total ? ` · swap ${fmtB(s.mem.swap_used)} / ${fmtB(s.mem.swap_total)}` : '');
  const rx = s.net.reduce((a, n) => a + n.rx, 0), tx = s.net.reduce((a, n) => a + n.tx, 0);
  $('netinfo').textContent = s.net.length
    ? `total ↓ ${fmtB(rx)}/s ↑ ${fmtB(tx)}/s · ` + s.net.map(n => `${esc(n.iface)} ↓${fmtB(n.rx)}/s ↑${fmtB(n.tx)}/s`).join(' · ')
    : 'no interfaces';
  pushHist(s.cpu.pct, memPct, rx, tx);
  charts.cpu.data.labels = hist.labels; charts.cpu.update();
  charts.mem.data.labels = hist.labels; charts.mem.update();
  charts.net.data.labels = hist.labels; charts.net.update();
  renderGpus(s.gpus);
  renderDisks(s.disks);
}
/* ---- token usage heatmap ---- */
let tokVersion = 0, tokDayVersion = 0;
const TOK_TYPES = [
  ['inputOther', 'in (fresh)', '#4f9cff'],
  ['inputCacheRead', 'cache read', '#3fb950'],
  ['inputCacheCreation', 'cache write', '#d29922'],
  ['output', 'output', '#e5534b'],
];
function fmtNum(n) { return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n); }
function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a.toFixed(2)})`;
}
async function tokPoll() {
  const version = ++tokVersion, source = $('toksource').value;
  let s;
  try {
    const r = await fetch('/api/tokens?days=30&source=' + source);
    if (r.status === 401) { location.reload(); return; }
    s = await r.json();
  } catch (e) { return; }
  if (version !== tokVersion) return;
  const days = s.days;
  let html = '<div class="tokrow tokhead"><span class="toklab"></span>' +
    days.map((d, i) => `<span class="tokday">${i % 5 === 4 || i === days.length - 1 ? d.date.slice(5) : ''}</span>`).join('') + '</div>';
  for (const [key, label, color] of TOK_TYPES) {
    const max = Math.max(1, ...days.map(d => d[key] || 0));
    html += `<div class="tokrow"><span class="toklab">${label}</span>` + days.map(d => {
      const v = d[key] || 0;
      const a = v > 0 ? 0.18 + 0.82 * Math.log10(v + 1) / Math.log10(max + 1) : 0.05;
      return `<span class="tokcell" data-date="${d.date}" style="background:${hexA(color, a)}" title="${d.date}  ${label}: ${fmtNum(v)}"></span>`;
    }).join('') + '</div>';
  }
  $('tokgrid').innerHTML = html;
  $('tokgrid').querySelectorAll('.tokcell').forEach(c => {
    if (c.dataset.date === selectedDate) c.classList.add('sel');
    c.onclick = () => tokDay(c.dataset.date, c);
  });
  const tot = {};
  for (const d of days) for (const [k] of TOK_TYPES) tot[k] = (tot[k] || 0) + (d[k] || 0);
  $('toksum').textContent = $('toksource').selectedOptions[0].textContent + ' · 30d total: ' + TOK_TYPES.map(([k, l]) => `${l} ${fmtNum(tot[k] || 0)}`).join(' · ');
}

let selectedDate = null;
async function tokDay(date, cell) {
  const version = ++tokDayVersion, source = $('toksource').value;
  selectedDate = date;
  $('tokgrid').querySelectorAll('.tokcell').forEach(x => x.classList.toggle('sel', x.dataset.date === date));
  let s;
  try {
    const r = await fetch('/api/tokens/day?date=' + encodeURIComponent(date) + '&source=' + source);
    if (r.status === 401) { location.reload(); return; }
    s = await r.json();
  } catch (e) { return; }
  if (version !== tokDayVersion || selectedDate !== date) return;
  const t = s.totals;
  let html = `<div class="tokdhead"><b>${s.date}</b>` +
    TOK_TYPES.map(([k, l]) => `<span class="tokdmeta">${l} ${fmtNum(t[k] || 0)}</span>`).join('') +
    `<span class="tokdmeta">${t.steps} steps</span><span style="flex:1"></span>` +
    `<button class="ghost" id="tokdclose">&#10005;</button></div>`;
  if (!s.sessions.length) {
    html += '<div class="dim">no usage this day</div>';
  } else {
    html += s.sessions.map(x => `<div class="tokdrow" title="${esc(x.cwd || x.id)}">
      <span class="tokdmeta">${x.provider === 'codex' ? 'Codex' : 'Kimi'}</span>
      <span class="tokdtitle">${esc(x.title || x.id.slice(0, 8))}</span>
      <span class="tokdmeta">${x.steps} steps</span>
      <span class="tokdmeta">in ${fmtNum(x.inputOther)}</span>
      <span class="tokdmeta">cache ${fmtNum(x.inputCacheRead + x.inputCacheCreation)}</span>
      <span class="tokdmeta">out ${fmtNum(x.output)}</span>
    </div>`).join('');
  }
  $('tokdetail').innerHTML = html;
  $('tokdetail').classList.remove('hidden');
  $('tokdclose').onclick = () => {
    $('tokdetail').classList.add('hidden');
    selectedDate = null;
    $('tokgrid').querySelectorAll('.tokcell').forEach(x => x.classList.remove('sel'));
  };
}

$('toksource').onchange = () => {
  tokDayVersion++;
  $('tokgrid').innerHTML = '';
  $('toksum').textContent = 'Loading…';
  $('tokdetail').classList.add('hidden');
  tokPoll();
  if (selectedDate) tokDay(selectedDate);
};

$('monbtn').onclick = () => {
  $('monmodal').classList.remove('hidden');
  if (!charts && window.Chart) makeCharts();
  monPoll();
  tokPoll();
  monTimer = setInterval(monPoll, 2000);
  tokTimer = setInterval(tokPoll, 30000);
};
$('monclose').onclick = () => {
  $('monmodal').classList.add('hidden');
  clearInterval(monTimer); monTimer = null;
  clearInterval(tokTimer); tokTimer = null;
};

refresh();
setInterval(refresh, 3000);

/* ---- published pages panel ---- */
function ago(t) {
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return 'now';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}
async function refreshPages() {
  let list = [];
  try {
    const r = await fetch('/api/pages');
    if (r.status === 401) return;
    list = await r.json();
  } catch (e) {}
  $('pageshead').classList.toggle('hidden', !list.length);
  const box = $('pages');
  box.innerHTML = '';
  for (const p of list) {
    const el = document.createElement('div');
    el.className = 'page';
    el.innerHTML = `<span class="name">${esc(p.title)}</span><span class="meta">${ago(p.mtime)}</span>` +
                   `<button class="ghost del" title="delete page">&#10005;</button>`;
    el.onclick = () => openPage(p);
    el.querySelector('.del').onclick = async ev => {
      ev.stopPropagation();
      await fetch('/api/page/del?name=' + encodeURIComponent(p.name));
      refreshPages();
    };
    box.appendChild(el);
  }
}
function openPage(p) {
  $('pgtitle').textContent = p.title;
  $('pgframe').src = '/pages/' + encodeURIComponent(p.name);
  $('pgmodal').classList.remove('hidden');
}
$('pgclose').onclick = () => {
  $('pgmodal').classList.add('hidden');
  $('pgframe').src = 'about:blank';
};
refreshPages();
</script>
</body>
</html>
"""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tmux web - login</title>
<style>
  body {
    margin: 0; height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0f1117; color: #d6dae3;
    font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  #card {
    background: #161a23; border: 1px solid #262c3a; border-radius: 10px;
    padding: 28px; width: 300px; display: flex; flex-direction: column; gap: 12px;
  }
  h1 { font-size: 17px; margin: 0 0 4px; }
  input {
    background: #0f1117; color: #d6dae3; border: 1px solid #262c3a;
    border-radius: 6px; padding: 9px 11px; outline: none; font-size: 15px;
  }
  input:focus { border-color: #4f9cff; }
  button {
    background: #4f9cff; color: #fff; border: 0; border-radius: 6px;
    padding: 9px; cursor: pointer; font-size: 14px;
  }
  #err { color: #e5534b; font-size: 13px; min-height: 18px; }
</style>
</head>
<body>
  <div id="card">
    <h1>&#9000;&#65039; tmux web</h1>
    <input id="pw" type="password" placeholder="password" autofocus>
    <button id="go">Sign in</button>
    <div id="err"></div>
  </div>
<script>
const pw = document.getElementById('pw'), err = document.getElementById('err');
async function login() {
  err.textContent = '';
  const r = await fetch('/api/login?password=' + encodeURIComponent(pw.value));
  if (r.ok) location.reload();
  else err.textContent = (await r.text()).trim() || 'login failed';
}
document.getElementById('go').onclick = login;
pw.addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
</script>
</body>
</html>
"""


def http_response(status: int, body: str, content_type: str, extra: dict | None = None) -> Response:
    headers = {"Content-Type": content_type, "Cache-Control": "no-store"}
    if extra:
        headers.update(extra)
    return Response(status, http.HTTPStatus(status).phrase, Headers(headers), body.encode())


def tmux(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["tmux", *args], capture_output=True, text=True, timeout=5)


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
PAGES_DIR = os.path.join(BASE_DIR, "pages")
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
            cookie = (f"tmux_web_token={new_token()}; Max-Age={TOKEN_TTL}; "
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
        if st["orig"] == "off":
            tmux("set-option", "-t", name, "mouse", "off")
        _attach_state.pop(name, None)
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
NODE_SECRET_FILE = os.path.join(BASE_DIR, ".node-secret")
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
    """'gpu1:work' -> ('gpu1', 'work') when gpu1 is connected, else (None, name)."""
    if ":" in name:
        node, _, rest = name.partition(":")
        if node in NODES and rest:
            return node, rest
    return None, name


def _qput(q: asyncio.Queue, item) -> None:
    try:
        q.put_nowait(item)
    except asyncio.QueueFull:
        pass  # slow client: drop rather than block the node link


class NodeConn:
    """One connected child node: request/response plumbing + stream fan-out."""

    def __init__(self, ws, name: str):
        self.ws = ws
        self.name = name
        self.sessions: dict[int, dict] = {}      # sid -> {name, cols, rows}
        self.pending: dict[int, asyncio.Future] = {}
        self.file_queues: dict[int, asyncio.Queue] = {}
        self.next_req = 0
        self.watchers: dict[int, set] = {}       # sid -> set of asyncio.Queue

    def _req_id(self) -> int:
        self.next_req += 1
        return self.next_req

    async def send_json(self, msg: dict) -> None:
        await self.ws.send(json.dumps(msg))

    async def request(self, msg: dict, timeout: float = 30) -> dict:
        rid = self._req_id()
        msg["id"] = rid
        fut = asyncio.get_running_loop().create_future()
        self.pending[rid] = fut
        try:
            await self.send_json(msg)
            return await asyncio.wait_for(fut, timeout)
        finally:
            self.pending.pop(rid, None)

    def send_input(self, sid: int, data: bytes) -> None:
        asyncio.create_task(self.ws.send(
            bytes([KIND_INPUT]) + sid.to_bytes(8, "big") + data))

    async def set_size(self, sid: int, cols: int, rows: int) -> None:
        await self.send_json({"type": "resize", "sid": sid, "cols": cols, "rows": rows})

    def sid_by_name(self, sname: str):
        for sid, s in self.sessions.items():
            if s["name"] == sname:
                return sid
        return None

    async def file_get(self, path: str, timeout: float = 30):
        """Start a file transfer; returns (meta, rid, chunk-queue)."""
        rid = self._req_id()
        q: asyncio.Queue = asyncio.Queue()
        self.file_queues[rid] = q
        fut = asyncio.get_running_loop().create_future()
        self.pending[rid] = fut
        try:
            await self.send_json({"type": "file-get", "id": rid, "path": path})
            meta = await asyncio.wait_for(fut, timeout)
        except Exception:
            self.file_queues.pop(rid, None)
            self.pending.pop(rid, None)
            raise
        self.pending.pop(rid, None)
        if not meta.get("ok"):
            self.file_queues.pop(rid, None)
        return meta, rid, q

    async def file_collect(self, rid: int, q: asyncio.Queue, limit: int):
        buf = bytearray()
        try:
            while True:
                item = await q.get()
                if item is None:
                    return bytes(buf), True
                buf += item
                if len(buf) > limit:
                    return bytes(buf), False
        finally:
            self.file_queues.pop(rid, None)

    async def handle_text(self, msg: dict) -> None:
        t = msg.get("type")
        rid = msg.get("id")
        if t in ("ack", "reply", "file-meta"):
            fut = self.pending.get(rid)
            if fut is not None and not fut.done():
                fut.set_result(msg)
        elif t == "file-end":
            q = self.file_queues.get(rid)
            if q is not None:
                _qput(q, None)
        elif t == "exit":
            sid = msg.get("sid")
            self.sessions.pop(sid, None)
            # Close bridges; web clients auto-reconnect and re-attach by name.
            for q in self.watchers.pop(sid, set()):
                _qput(q, None)


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
        for s in hello.get("sessions", []):
            node.sessions[int(s["sid"])] = {
                "name": str(s.get("name", ""))[:64],
                "cols": int(s.get("cols", 220)), "rows": int(s.get("rows", 50))}
    except (ValueError, KeyError, TypeError, ConnectionError, asyncio.TimeoutError):
        await ws.close(1008, "node authentication failed")
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
        for qs in node.watchers.values():
            for q in qs:
                _qput(q, None)
        for fut in node.pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("node disconnected"))
        for q in node.file_queues.values():
            _qput(q, None)


async def handle_node_attach(ws, node: NodeConn, key: str, sname: str) -> None:
    """Bridge a web client's websocket to a session living on a child node."""
    sid = node.sid_by_name(sname)
    if sid is None:
        await ws.close(4004, "no such session on node")
        return
    cols, rows = _last_size.get(key, (220, 50))
    cid = id(ws)
    web_attach(key, cid, cols, rows)
    queue: asyncio.Queue = asyncio.Queue(maxsize=256)
    watches = node.watchers.setdefault(sid, set())
    watches.add(queue)
    if len(watches) == 1:
        await node.send_json({"type": "watch", "sid": sid, "cols": cols, "rows": rows})

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

    t_out = asyncio.create_task(node_to_ws())
    t_in = asyncio.create_task(ws_to_node())
    try:
        await asyncio.wait({t_out, t_in}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        t_out.cancel()
        t_in.cancel()
        watches.discard(queue)
        if not watches:
            node.watchers.pop(sid, None)
            try:
                await node.send_json({"type": "unwatch", "sid": sid})
            except Exception:
                pass
        web_detach(key, cid)


# ---------------------------------------------------------------------------
# File upload over a dedicated websocket: client sends a JSON header
# {"name": ..., "size": ...}, then raw binary frames until <size> bytes have
# been sent; the server replies {"ok": true, "path": ...}.
# With ?node=<name> the file lands on that child node instead.
# ---------------------------------------------------------------------------
UPLOAD_DIR = "/tmp/tmux-web-uploads"
MAX_UPLOAD = 2 * 1024**3  # 2 GiB


def _safe_name(name: str) -> str:
    name = os.path.basename(name).strip()[:128]
    if name in ("", ".", ".."):
        name = "file"
    return name


def _cleanup_uploads() -> None:
    """Drop upload dirs older than a day; they are meant to be temporary."""
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

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    updir = tempfile.mkdtemp(prefix="up-", dir=UPLOAD_DIR)
    os.chmod(updir, 0o700)
    path = os.path.join(updir, name)
    received = 0
    try:
        with open(path, "wb") as f:
            while received < size:
                msg = await ws.recv()
                if not isinstance(msg, (bytes, bytearray)):
                    continue
                f.write(msg)
                received += len(msg)
        os.chmod(path, 0o600)
        await ws.send(json.dumps({"ok": True, "path": path, "size": received}))
    except (Exception, asyncio.CancelledError) as e:
        try:
            await ws.send(json.dumps({"ok": False, "error": str(e)}))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass


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
    try:
        await node.send_json({"type": "file-put", "id": rid, "name": name, "size": size})
        received = 0
        while received < size:
            msg = await ws.recv()
            if not isinstance(msg, (bytes, bytearray)):
                continue
            await node.ws.send(bytes([KIND_FILE_PUT]) + rid.to_bytes(8, "big") + bytes(msg))
            received += len(msg)
        await node.send_json({"type": "file-put-done", "id": rid})
        r = await asyncio.wait_for(fut, 300)
        if r.get("ok"):
            await ws.send(json.dumps({"ok": True, "path": r.get("path", ""), "size": received}))
        else:
            await ws.send(json.dumps({"ok": False, "error": r.get("error", "node upload failed")}))
    except (Exception, asyncio.CancelledError) as e:
        try:
            await ws.send(json.dumps({"ok": False, "error": str(e)}))
        except Exception:
            pass
    finally:
        node.pending.pop(rid, None)
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
        if not host or not (0 < port < 65536):
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

    await asyncio.gather(ws_to_tcp(), tcp_to_ws())
    try:
        writer.close()
    except Exception:
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
        await handle_node_attach(ws, NODES[nname], name, sname)
        return

    # Start the pty at the size this session's client last used, so the
    # first frame is already right; the client sends an explicit resize
    # right after connect to correct it if needed.
    cols, rows = _last_size.get(name, (220, 50))
    cid = id(ws)
    web_attach(name, cid, cols, rows)
    pid, fd = pty.fork()
    if pid == 0:  # child
        env = dict(os.environ, TERM="xterm-256color")
        try:
            os.execvpe("tmux", ["tmux", "attach-session", "-t", name], env)
        finally:
            os._exit(127)

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=256)
    set_winsize(fd, cols, rows)

    def on_readable() -> None:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        if data:
            try:
                queue.put_nowait(data)
            except asyncio.QueueFull:
                pass  # slow client: drop rather than block tmux
        else:
            loop.remove_reader(fd)
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                pass

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
                os.write(fd, msg)

    t_out = asyncio.create_task(pty_to_ws())
    t_in = asyncio.create_task(ws_to_pty())
    try:
        await asyncio.wait({t_out, t_in}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        t_out.cancel()
        t_in.cancel()
        web_detach(name, cid)
        loop.remove_reader(fd)
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.kill(pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        try:
            # Reap in a worker thread: a stubborn child must never block
            # the event loop (a plain os.waitpid here once froze the whole
            # server when a tmux client ignored SIGHUP).
            await loop.run_in_executor(None, os.waitpid, pid, 0)
        except ChildProcessError:
            pass


async def main() -> None:
    global _TOKENS
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
