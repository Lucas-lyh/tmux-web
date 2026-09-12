"""Connection-owned node requests, transfers and subscriptions."""
import asyncio
import json
from node import KIND_INPUT
from hub.queues import offer_output as _qput

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
        self.capabilities = frozenset()
        self.closed = False
        self.tasks = set()

    def spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        def done(completed):
            self.tasks.discard(completed)
            if not completed.cancelled():
                completed.exception()
        task.add_done_callback(done)
        return task

    async def close(self):
        if self.closed:
            return
        self.closed = True
        for groups in self.watchers.values():
            for queue in groups:
                _qput(queue, None)
        for future in self.pending.values():
            if not future.done():
                future.set_exception(ConnectionError('node disconnected'))
        for queue in self.file_queues.values():
            _qput(queue, None)
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self.ws.close()

    def _req_id(self) -> int:
        self.next_req += 1
        return self.next_req

    async def send_json(self, msg: dict) -> None:
        if self.closed:
            raise ConnectionError('node disconnected')
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
        if self.closed:
            raise ConnectionError('node disconnected')
        self.spawn(self.ws.send(
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
        except BaseException:
            self.file_queues.pop(rid, None)
            self.pending.pop(rid, None)
            raise
        self.pending.pop(rid, None)
        if not meta.get("ok"):
            self.file_queues.pop(rid, None)
        return meta, rid, q

    async def file_stat(self, path):
        if 'file-stat' in self.capabilities:
            return await self.request({'type': 'file-stat', 'path': path})
        # Old node.py has no metadata-only message. Retain its existing
        # response path instead of sending a request it would ignore.
        meta, rid, _ = await self.file_get(path)
        self.file_queues.pop(rid, None)
        return meta

    async def file_collect(self, rid: int, q: asyncio.Queue, limit: int):
        buf = bytearray()
        try:
            while True:
                item = await asyncio.wait_for(q.get(), 60)
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
                await q.put(None)
        elif t == 'input-error':
            for queue in self.watchers.get(msg.get('sid'), ()):
                _qput(queue, b'\r\n[tmux-web] terminal input queue is full; input was rejected.\r\n')
        elif t == "exit":
            sid = msg.get("sid")
            self.sessions.pop(sid, None)
            # Close bridges; web clients auto-reconnect and re-attach by name.
            for q in self.watchers.pop(sid, set()):
                _qput(q, None)
