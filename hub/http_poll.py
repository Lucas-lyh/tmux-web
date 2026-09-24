"""Bounded HTTP record transport for the existing Noise node protocol."""
import asyncio
import secrets
import time
from types import SimpleNamespace
from aiohttp import web

HEADERS = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}


class PollChannel:
    def __init__(self, key):
        from urllib.parse import urlencode
        self.request = SimpleNamespace(path='/ws-node?' + urlencode({'v': '2', 'key': key}))
        self.incoming = asyncio.Queue(16)
        self.outgoing = asyncio.Queue(16)
        self.closed = False
        self.updated = time.monotonic()
        self.sequences = {'send': 0, 'recv': 0}
        self.busy = set()

    async def send(self, data):
        if self.closed:
            raise ConnectionError('HTTP channel closed')
        try:
            await asyncio.wait_for(self.outgoing.put(data), 30)
        except asyncio.TimeoutError:
            raise ConnectionError('HTTP receiver stalled') from None

    async def recv(self):
        data = await self.incoming.get()
        if data is None:
            raise ConnectionError('HTTP channel closed')
        return data

    async def close(self, code=1000, reason=''):
        self.closed = True
        for queue in (self.incoming, self.outgoing):
            while not queue.empty():
                queue.get_nowait()
            queue.put_nowait(None)


def install(app, backend):
    channels = {}
    tasks = set()

    async def run(channel, sid):
        try:
            await backend.handle_node_ws(channel)
        except (ConnectionError, OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            await channel.close()
            channels.pop(sid, None)

    async def lifecycle(app):
        async def sweep():
            while True:
                await asyncio.sleep(5)
                for channel in list(channels.values()):
                    if time.monotonic() - channel.updated > 45:
                        await channel.close()
        sweeper = asyncio.create_task(sweep())
        yield
        sweeper.cancel()
        for task in list(tasks):
            task.cancel()
        await asyncio.gather(sweeper, *tasks, return_exceptions=True)
    app.cleanup_ctx.append(lifecycle)

    async def handle(request):
        if request.method != 'POST':
            return web.Response(status=405, headers={**HEADERS, 'Allow': 'POST'})
        if request.content_length is not None and request.content_length > 65535:
            return web.Response(status=413, headers=HEADERS)
        body = bytearray()
        async for chunk in request.content.iter_chunked(8192):
            body.extend(chunk)
            if len(body) > 65535:
                return web.Response(status=413, headers=HEADERS)
        action = request.match_info['action']
        if action == 'open':
            key = request.query.get('key', '')
            if body or len(key) > 64:
                return web.Response(status=400, headers=HEADERS)
            if len(channels) >= 256:
                return web.Response(status=503, headers=HEADERS)
            sid = secrets.token_hex(32)
            channel = channels[sid] = PollChannel(key)
            task = asyncio.create_task(run(channel, sid))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            return web.Response(text=sid, headers=HEADERS)
        channel = channels.get(request.query.get('sid', ''))
        if channel is None or channel.closed:
            return web.Response(status=410, headers=HEADERS)
        channel.updated = time.monotonic()
        if action == 'close':
            await channel.close()
            return web.Response(status=204, headers=HEADERS)
        if action not in ('send', 'recv'):
            return web.Response(status=404, headers=HEADERS)
        # Never replay records after uncertain delivery. Sequence errors terminate
        # the channel; the client reconnects with a fresh Noise handshake.
        if (action in channel.busy or request.query.get('seq') != str(channel.sequences[action])
                or (action == 'recv' and body) or (action == 'send' and not body)):
            await channel.close()
            return web.Response(status=409, headers=HEADERS)
        channel.sequences[action] += 1
        channel.busy.add(action)
        try:
            if action == 'send':
                await asyncio.wait_for(channel.incoming.put(bytes(body)), 25)
                return web.Response(status=204, headers=HEADERS)
            try:
                data = await asyncio.wait_for(channel.outgoing.get(), 15)
            except asyncio.TimeoutError:
                return web.Response(status=204, headers=HEADERS)
            if data is None:
                return web.Response(status=410, headers=HEADERS)
            return web.Response(body=data, content_type='application/octet-stream', headers=HEADERS)
        except asyncio.TimeoutError:
            await channel.close()
            return web.Response(status=408, headers=HEADERS)
        finally:
            channel.busy.discard(action)
    app.router.add_route('*', '/node-http/{action}', handle)
