"""Short-lived enrollment grants and independently revocable node credentials.

Only opaque key identifiers travel outside Noise. Neither kind of credential
is an operator API token. Historical shared node secrets remain separate.
"""
import copy
import json
import re
import secrets
import threading
import time
from pathlib import Path

from .storage import atomic_json

SELECTOR = re.compile(r"(twj|twn)\.([0-9a-f]{32})\Z")


class NodeCredentials:
    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.RLock()
        self.claimed = set()
        self.records = None

    def _load(self):
        if self.records is None:
            try:
                data = json.loads(self.path.read_text())
            except FileNotFoundError:
                data = {"version": 1, "nodes": {}}
            if data.get("version") != 1 or not isinstance(data.get("nodes"), dict):
                raise ValueError("invalid node credential state")
            self.records = data["nodes"]
        return self.records

    def _save(self, records):
        try:
            atomic_json(str(self.path), {"version": 1, "nodes": records})
        except BaseException:
            # os.replace may have succeeded before directory fsync failed.
            # Never keep authorizing from an older in-memory snapshot.
            self.records = None
            try:
                self._load()
            except (OSError, ValueError):
                self.records = {}  # Unreadable state cannot authorize a node.
            raise
        self.records = records

    def issue(self, ttl=600):
        with self.lock:
            now = self.clock()
            records = {k: copy.copy(v) for k, v in self._load().items()
                       if v.get("token") or v.get("expires", 0) > now}
            if sum(bool(v.get("join")) and v.get("expires", 0) > now for v in records.values()) >= 100:
                raise ValueError("too many pending enrollment commands")
            key = secrets.token_hex(16)
            token = "twj." + key + "." + secrets.token_hex(32)
            records[key] = {"join": token, "expires": now + ttl, "created": now}
            self._save(records)
            return token

    def lookup(self, selector):
        with self.lock:
            match = SELECTOR.fullmatch(selector)
            if not match:
                raise ValueError("invalid node credential identifier")
            kind, key = match.groups()
            record = self._load().get(key, {})
            token = record.get("token") if kind == "twn" else (
                record.get("join") if record.get("expires", 0) > self.clock() else None)
            if not token:
                raise ValueError("node credential expired or revoked")
            return token

    def prepare(self, selector, name, authenticated_token):
        """Claim only after Noise authentication; persist before sending a key."""
        with self.lock:
            if not secrets.compare_digest(self.lookup(selector), authenticated_token):
                raise ValueError("node credential changed")
            kind, key = selector.split(".")
            record = self._load()[key]
            if record.get("name", name) != name:
                raise ValueError("node credential belongs to another node")
            if kind == "twn":
                # A reconnect with the saved permanent key also completes a
                # handoff whose acknowledgement was lost in transit.
                if record.get("join"):
                    records = copy.deepcopy(self.records)
                    records[key].pop("join", None)
                    self._save(records)
                return key, None
            if key in self.claimed:
                raise ValueError("enrollment already in progress")
            records = copy.deepcopy(self.records)
            records[key]["name"] = name
            records[key].setdefault("token", "twn." + key + "." + secrets.token_hex(32))
            self._save(records)
            self.claimed.add(key)
            return key, records[key]["token"]

    def complete(self, key):
        with self.lock:
            if key not in self._load():
                raise ValueError("node credential revoked")
            records = copy.deepcopy(self.records)
            records[key].pop("join", None)
            self._save(records)
            self.claimed.discard(key)

    def release(self, key):
        with self.lock:
            self.claimed.discard(key)

    def active(self, key):
        # Snapshots are replaced, never mutated after publication. The hub can
        # check this without yielding between the check and node registration.
        return bool((self.records or {}).get(key, {}).get("token"))

    def revoke(self, key):
        with self.lock:
            if key not in self._load():
                return False
            records = copy.deepcopy(self.records)
            records.pop(key)
            self._save(records)
            self.claimed.discard(key)
            return True

    def public_records(self):
        with self.lock:
            return [{"id": key, "name": value["name"]}
                    for key, value in self._load().items()
                    if value.get("token") and value.get("name")]
