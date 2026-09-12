"""Incremental JSONL readers and Kimi usage aggregation.

Only complete newline-terminated records are consumed. An inode replacement,
truncation, same-size rewrite, or changed append anchor rebuilds that file.
Warm queries stat files but neither reread nor reparse their contents.
"""
import copy
import datetime
import glob
import json
import math
import os
from pathlib import Path
import threading

TOKEN_KEYS = ("inputOther", "inputCacheRead", "inputCacheCreation", "output")
KIMI_SESSIONS_DIR = os.path.expanduser("~/.kimi-code/sessions")


def counters(value, keys=TOKEN_KEYS):
    if not isinstance(value, dict):
        raise ValueError("usage must be an object")
    result = []
    for key in keys:
        number = value.get(key, 0)
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise ValueError("token counts must be non-negative integers")
        result.append(number)
    return tuple(result)


def empty_totals():
    return dict.fromkeys((*TOKEN_KEYS, "steps"), 0)


class IncrementalJSONL:
    CHUNK = 64 * 1024
    ANCHOR = 128

    def __init__(self, path, factory, accept=None):
        self.path, self.factory, self.accept = path, factory, accept
        self.consumer = factory(path)
        self.offset = 0
        self.pending = b""
        self.anchor = b""
        self.signature = None
        self.bytes_read = 0
        self.parsed_lines = 0
        self.rebuilds = 0
        self.revision = 0
        self.parse_errors = 0

    def refresh(self):
        stat = os.stat(self.path)
        signature = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        if signature == self.signature:
            return False
        with open(self.path, "rb") as stream:
            stat = os.fstat(stream.fileno())
            signature = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
            reset = self.signature is not None and (
                signature[:2] != self.signature[:2] or stat.st_size < self.offset
                or (stat.st_size == self.offset and signature != self.signature)
            )
            if not reset and self.offset:
                stream.seek(max(0, self.offset - len(self.anchor)))
                reset = stream.read(len(self.anchor)) != self.anchor
            if reset:
                self.consumer = self.factory(self.path)
                self.offset, self.pending, self.anchor = 0, b"", b""
                self.rebuilds += 1
                self.parse_errors = 0
            stream.seek(self.offset)
            remaining = max(0, stat.st_size - self.offset)
            while remaining:
                chunk = stream.read(min(self.CHUNK, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                self.offset += len(chunk)
                self.bytes_read += len(chunk)
                self.anchor = (self.anchor + chunk)[-self.ANCHOR:]
                lines = (self.pending + chunk).split(b"\n")
                self.pending = lines.pop()
                for line in lines:
                    if self.accept is not None and not self.accept(line):
                        continue
                    try:
                        data = json.loads(line)
                        self.parsed_lines += 1
                        if self.consumer.feed(data) is False:
                            self.parse_errors += 1
                    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, OSError):
                        # One malformed row must not discard valid later rows.
                        self.parse_errors += 1
                        continue
            self.signature = signature
            self.revision += 1
        return True


class _KimiFile:
    def __init__(self, path):
        self.days = {}

    def feed(self, data):
        if not isinstance(data, dict):
            return False
        event = data.get("event")
        event = event if isinstance(event, dict) else {}
        usage = event.get("usage") or data.get("usage")
        if not isinstance(usage, dict) or not usage:
            return False
        values = counters(usage)
        stamp = data.get("time") or event.get("time")
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or not math.isfinite(stamp):
            return False
        day = datetime.datetime.fromtimestamp(stamp / 1000).date().isoformat()
        total = self.days.setdefault(day, empty_totals())
        for key, value in zip(TOKEN_KEYS, values):
            total[key] += value
        total["steps"] += 1
        return True


_token_cache = {}
_meta_cache = {}
_lock = threading.RLock()
_kimi_files = {}
_kimi_totals = {}
_kimi_sessions = {}
_kimi_session_dirs = {}


def _wire_daily(path, mtime=None):
    """Compatibility entry point; mtime is accepted but stat identity is authoritative."""
    with _lock:
        tail = _token_cache.get(path)
        if tail is None:
            tail = _token_cache[path] = IncrementalJSONL(
                path, _KimiFile, lambda line: b'"usage"' in line)
        try:
            tail.refresh()
        except OSError:
            _token_cache.pop(path, None)
            return {}
        return copy.deepcopy(tail.consumer.days)


def _adjust(target, day, values, sign):
    total = target.setdefault(day, empty_totals())
    for key in (*TOKEN_KEYS, "steps"):
        total[key] += sign * values[key]
    if not any(total.values()):
        target.pop(day, None)


def _remove_kimi_file(path):
    previous = _kimi_files.pop(path, None)
    if previous is None:
        return
    sid, days, _ = previous
    for day, values in days.items():
        _adjust(_kimi_totals, day, values, -1)
        _adjust(_kimi_sessions[sid], day, values, -1)
    if not _kimi_sessions.get(sid):
        _kimi_sessions.pop(sid, None)


def _refresh_kimi(sessions_dir):
    paths = set(glob.glob(os.path.join(
        sessions_dir, "*", "session_*", "agents", "*", "wire.jsonl")))
    for path in set(_kimi_files) - paths:
        _remove_kimi_file(path)
    for path in set(_token_cache) - paths:
        _token_cache.pop(path, None)
    directories = {}
    for path in sorted(paths):
        try:
            tail = _token_cache.get(path)
            if tail is None:
                tail = _token_cache[path] = IncrementalJSONL(
                    path, _KimiFile, lambda line: b'"usage"' in line)
            changed = tail.refresh()
        except OSError:
            _remove_kimi_file(path)
            _token_cache.pop(path, None)
            continue
        session_dir = str(Path(path).parents[2])
        sid = Path(session_dir).name.removeprefix("session_")
        directories.setdefault(sid, session_dir)
        previous = _kimi_files.get(path)
        if changed or previous is None or previous[2] != (tail.consumer, tail.revision):
            _remove_kimi_file(path)
            days = copy.deepcopy(tail.consumer.days)
            session_days = _kimi_sessions.setdefault(sid, {})
            for day, values in days.items():
                _adjust(_kimi_totals, day, values, 1)
                _adjust(session_days, day, values, 1)
            _kimi_files[path] = (sid, days, (tail.consumer, tail.revision))
    _kimi_session_dirs.clear()
    _kimi_session_dirs.update(directories)
    meta_paths = {os.path.join(directory, "state.json") for directory in directories.values()}
    for path in set(_meta_cache) - meta_paths:
        _meta_cache.pop(path, None)


def _session_metadata(directory):
    path = os.path.join(directory, "state.json")
    try:
        stat = os.stat(path)
        signature = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        cached = _meta_cache.get(path)
        if cached is not None and cached[0] == signature:
            return cached[1]
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict):
            raise ValueError("session metadata must be an object")
        title = data.get("title") or data.get("lastPrompt") or ""
        cwd = data.get("cwd") or ""
        result = (title[:80] if isinstance(title, str) else "",
                  cwd if isinstance(cwd, str) else "")
        _meta_cache[path] = (signature, result)
        return result
    except (OSError, ValueError, TypeError):
        _meta_cache.pop(path, None)
        return "", ""


def _kimi_token_stats(days=30, sessions_dir=None):
    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        raise ValueError("days must be a positive integer")
    with _lock:
        _refresh_kimi(sessions_dir or KIMI_SESSIONS_DIR)
        today = datetime.date.today()
        dates = [(today - datetime.timedelta(days=i)).isoformat() for i in reversed(range(days))]
        return {"types": list(TOKEN_KEYS), "parse_errors": sum(tail.parse_errors for tail in _token_cache.values()), "days": [
            {"date": date, **{key: _kimi_totals.get(date, {}).get(key, 0) for key in TOKEN_KEYS}}
            for date in dates
        ]}


def _kimi_token_day(date, sessions_dir=None):
    datetime.date.fromisoformat(date)
    with _lock:
        _refresh_kimi(sessions_dir or KIMI_SESSIONS_DIR)
        sessions = []
        for sid, days in _kimi_sessions.items():
            values = days.get(date)
            if values is None:
                continue
            title, cwd = _session_metadata(_kimi_session_dirs.get(sid, ""))
            sessions.append({"id": sid, "title": title, "cwd": cwd, **values})
        sessions.sort(key=lambda item: -sum(item[key] for key in TOKEN_KEYS))
        return {"date": date, "totals": dict(_kimi_totals.get(date, empty_totals())), "sessions": sessions,
                "parse_errors": sum(tail.parse_errors for tail in _token_cache.values())}
