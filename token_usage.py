"""Incremental Codex usage accounting with snapshot/detail overlap reconciliation."""
import bisect
import datetime
import glob
import os
import threading

from hub.usage import IncrementalJSONL, TOKEN_KEYS, counters, empty_totals

CODEX_HOME = os.path.expanduser(os.environ.get("CODEX_HOME", "~/.codex"))
RAW_KEYS = ("input_tokens", "cached_input_tokens", "cache_write_input_tokens", "output_tokens")
_cache = {}
_lock = threading.RLock()


def _raw(value):
    values = counters(value, RAW_KEYS)
    if values[1] + values[2] > values[0]:
        raise ValueError("cached usage exceeds total input")
    return values


def _categories(raw):
    return (raw[0] - raw[1] - raw[2], raw[1], raw[2], raw[3])


def _usage(value):
    return dict(zip(TOKEN_KEYS, _categories(_raw(value))))


class _CodexFile:
    def __init__(self, path):
        self.meta = {"id": os.path.basename(path), "cwd": ""}
        self.have_meta = False
        self.events = []
        self.previous = (0, 0, 0, 0)
        self.epoch = 0
        self.records = set()
        self.highwater = (0, 0, 0, 0)
        self.highwater_time = float("-inf")
        self.snapshot_time = float("-inf")
        self.resets = []

    def _reset(self, stamp, raw):
        self.epoch += 1
        self.previous = (0, 0, 0, 0)
        self.highwater = (0, 0, 0, 0)
        self.resets.append((stamp, _categories(raw)))

    def feed(self, data):
        if not isinstance(data, dict) or not isinstance(data.get("payload"), dict):
            return False
        payload = data["payload"]
        kind = data.get("type")
        if kind == "session_meta":
            if not self.have_meta and isinstance(payload.get("id"), str) and payload["id"]:
                self.meta = {
                    "id": payload["id"], "cwd": payload.get("cwd") if isinstance(payload.get("cwd"), str) else "",
                    "forked_from_id": payload.get("forked_from_id"),
                    "timestamp": data.get("timestamp") if isinstance(data.get("timestamp"), str) else "",
                }
                self.have_meta = True
                return True
            return None
        stamp = data.get("timestamp")
        if not isinstance(stamp, str):
            return False
        instant = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone()
        day, timestamp = instant.date().isoformat(), instant.timestamp()
        sid = self.meta["id"]
        if kind == "token_usage_record":
            if payload.get("thread_id", sid) != sid:
                return None
            values = _categories(_raw(payload.get("usage")))
            response = payload.get("response_id")
            if response is not None and not isinstance(response, str):
                return False
            if response and (sid, "record", response) in self.records:
                return None
            total = payload.get("thread_token_usage")
            raw_total = _raw(total) if isinstance(total, dict) else None
            if raw_total is not None:
                # A newer detail with lower cumulative counters identifies a
                # reset before its corresponding snapshot has arrived. Older
                # details are reconciled into their historical epoch instead.
                if timestamp > self.highwater_time and (
                    raw_total[0] < self.highwater[0] or raw_total[3] < self.highwater[3]
                ):
                    self._reset(timestamp, raw_total)
                if timestamp >= self.highwater_time:
                    self.highwater, self.highwater_time = raw_total, timestamp
            end = _categories(raw_total) if raw_total is not None else None
            response = payload.get("response_id")
            if response is not None and not isinstance(response, str):
                return False
            key = (sid, "record", response) if response else (sid, "record", self.epoch, stamp, values, end)
            if key in self.records:
                return None
            self.records.add(key)
            start = tuple(max(0, e - amount) for e, amount in zip(end, values)) if end is not None else None
            self.events.append({
                "key": key, "sid": sid, "epoch": self.epoch, "day": day, "timestamp": timestamp,
                "kind": "record", "values": values, "start": start, "end": end,
            })
        elif kind == "event_msg" and payload.get("type") == "token_count":
            info = payload.get("info")
            if not isinstance(info, dict) or not isinstance(info.get("total_token_usage"), dict):
                return False
            raw = _raw(info["total_token_usage"])
            # A lower counter begins a new epoch before duplicate suppression.
            if timestamp >= self.snapshot_time and (
                raw[0] < self.previous[0] or raw[3] < self.previous[3]
            ):
                self._reset(timestamp, raw)
            if timestamp >= self.highwater_time:
                self.highwater, self.highwater_time = raw, timestamp
            self.snapshot_time = max(self.snapshot_time, timestamp)
            start, end = _categories(self.previous), _categories(raw)
            self.previous = raw
            if self.meta.get("forked_from_id") and stamp < self.meta.get("timestamp", ""):
                return None
            if not any(e > s for s, e in zip(start, end)):
                return None
            self.events.append({
                "key": (sid, "snapshot", self.epoch, raw), "sid": sid,
                "epoch": self.epoch, "day": day, "timestamp": timestamp, "kind": "snapshot",
                "values": tuple(max(0, e - s) for s, e in zip(start, end)),
                "start": start, "end": end,
            })


class _Intervals:
    """Non-overlapping cumulative counter spans; details supersede snapshots."""
    def __init__(self):
        self.starts = []
        self.parts = []  # (start, end, owning event key, priority)

    def add(self, start, end, key, priority, adjust):
        if end <= start:
            return
        if not self.parts or start >= self.parts[-1][1]:
            self.starts.append(start)
            self.parts.append((start, end, key, priority))
            adjust(key, end - start)
            return
        index = max(0, bisect.bisect_right(self.starts, start) - 1)
        while index < len(self.parts) and self.parts[index][1] <= start:
            index += 1
        stop = index
        replacement = []
        cursor = start
        while stop < len(self.parts) and self.parts[stop][0] < end:
            left, right, owner, old_priority = self.parts[stop]
            if left > cursor:
                replacement.append((cursor, min(left, end), key, priority))
                adjust(key, min(left, end) - cursor)
                cursor = min(left, end)
            if left < start:
                replacement.append((left, start, owner, old_priority))
            overlap_left, overlap_right = max(left, start), min(right, end)
            if overlap_right > overlap_left:
                if priority > old_priority:
                    replacement.append((overlap_left, overlap_right, key, priority))
                    adjust(owner, overlap_left - overlap_right)
                    adjust(key, overlap_right - overlap_left)
                else:
                    replacement.append((overlap_left, overlap_right, owner, old_priority))
                cursor = max(cursor, overlap_right)
            if right > end:
                replacement.append((end, right, owner, old_priority))
            stop += 1
        if cursor < end:
            replacement.append((cursor, end, key, priority))
            adjust(key, end - cursor)
        self.parts[index:stop] = replacement
        self.starts[index:stop] = [part[0] for part in replacement]


class _SessionLedger:
    def __init__(self, meta, reset_points=()):
        self.meta = dict(meta)
        self.reset_points = reset_points
        self.boundaries = tuple(sorted({stamp for stamp, _ in reset_points}))
        self.events = {}
        self.epochs = {}
        self.days = {}

    def _measure(self, key, dimension, delta):
        event = self.events[key]
        total = self.days.setdefault(event["day"], empty_totals())
        before = any(event["measure"]) or event["kind"] == "record"
        event["measure"][dimension] += delta
        total[TOKEN_KEYS[dimension]] += delta
        after = any(event["measure"]) or event["kind"] == "record"
        total["steps"] += int(after) - int(before)
        if not any(total.values()):
            self.days.pop(event["day"], None)

    def add(self, source):
        source = dict(source)
        # Reset timestamps found in any copy align partial/archived files.
        # Tied timestamps cannot order a partial log unambiguously: retain the
        # epoch evidenced by that file's own counter sequence in that case.
        epoch = (source["epoch"] if source["timestamp"] in self.boundaries
                 else bisect.bisect_left(self.boundaries, source["timestamp"]))
        key = source["key"]
        if (source["kind"] == "record" and len(key) == 3
                and not source.get("file_has_resets")
                and (source["timestamp"], source["end"]) in self.reset_points):
            # A partial file's identified response matches the timestamp and
            # cumulative total of a reset observed in another copy.
            epoch = bisect.bisect_right(self.boundaries, source["timestamp"])
        source["epoch"] = epoch
        if source["kind"] == "snapshot" or len(key) > 3:
            key = (*key[:2], epoch, *key[3:])
            source["key"] = key
        if source["kind"] == "record" and key in self.events:
            return
        if key not in self.events:
            self.events[key] = {**source, "measure": [0, 0, 0, 0]}
            if source["kind"] == "record":
                self.days.setdefault(source["day"], empty_totals())["steps"] += 1
        if source["start"] is None:
            for dimension, amount in enumerate(source["values"]):
                self._measure(key, dimension, amount)
            return
        intervals = self.epochs.setdefault(source["epoch"], [_Intervals() for _ in TOKEN_KEYS])
        priority = 2 if source["kind"] == "record" else 1
        for dimension, (start, end) in enumerate(zip(source["start"], source["end"])):
            intervals[dimension].add(
                start, end, key, priority,
                lambda owner, delta, dim=dimension: self._measure(owner, dim, delta),
            )


class _Index:
    def __init__(self):
        self.files = {}
        self.sessions = {}
        self.applied_events = 0
        self.rebuilt_sessions = 0

    def sync(self, current):
        reset_points = {}
        for consumer in current.values():
            reset_points.setdefault(consumer.meta["id"], set()).update(consumer.resets)
        reset_points = {sid: tuple(sorted(values)) for sid, values in reset_points.items()}
        affected = {sid for sid, ledger in self.sessions.items()
                    if ledger.reset_points != reset_points.get(sid, ())}
        for path, (old, _) in self.files.items():
            new = current.get(path)
            if new is not old:
                affected.add(old.meta["id"])
                if new is not None:
                    affected.add(new.meta["id"])
        for sid in affected:
            self.sessions.pop(sid, None)
            self.rebuilt_sessions += 1
        for path, consumer in current.items():
            previous = self.files.get(path)
            start = 0 if consumer.meta["id"] in affected or previous is None or previous[0] is not consumer else previous[1]
            if start < len(consumer.events):
                ledger = self.sessions.setdefault(consumer.meta["id"], _SessionLedger(consumer.meta, reset_points.get(consumer.meta["id"], ())))
                for event in consumer.events[start:]:
                    ledger.add({**event, "file_has_resets": bool(consumer.resets)})
                    self.applied_events += 1
        self.files = {path: (consumer, len(consumer.events)) for path, consumer in current.items()}


_index = _Index()


def codex_sessions(cutoff):
    """Return per-session local-day totals; unchanged logs do no parse/aggregation work."""
    datetime.date.fromisoformat(cutoff)
    with _lock:
        paths = sorted({path for folder in ("sessions", "archived_sessions")
                        for path in glob.glob(os.path.join(CODEX_HOME, folder, "**", "*.jsonl"), recursive=True)})
        current = {}
        for path in paths:
            try:
                tail = _cache.get(path)
                if tail is None:
                    tail = _cache[path] = IncrementalJSONL(
                        path, _CodexFile,
                        lambda line: any(token in line for token in (
                            b'"session_meta"', b'"token_usage_record"', b'"token_count"')),
                    )
                tail.refresh()
                current[path] = tail.consumer
            except OSError:
                _cache.pop(path, None)
        for path in set(_cache) - set(current):
            _cache.pop(path, None)
        _index.sync(current)
        result = []
        for sid, ledger in _index.sessions.items():
            days = {day: dict(values) for day, values in ledger.days.items() if day >= cutoff and any(values.values())}
            if not days:
                continue
            cwd = ledger.meta.get("cwd", "")
            result.append({"id": sid, "provider": "codex",
                           "title": os.path.basename(cwd) or sid[:8], "cwd": cwd, "days": days})
        return result



def codex_diagnostics():
    """Diagnostics for the current scan; counts malformed usage-bearing rows."""
    with _lock:
        return {"files": len(_cache), "parse_errors": sum(tail.parse_errors for tail in _cache.values()),
                "bytes_read": sum(tail.bytes_read for tail in _cache.values()),
                "parsed_lines": sum(tail.parsed_lines for tail in _cache.values())}
