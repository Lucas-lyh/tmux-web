import asyncio
import json
import socket
import os
import secrets
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiohttp import web, ClientSession, WSMsgType
from aiohttp.test_utils import TestServer

import http_frontend as frontend
import node
import server


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.received = []

        async def target(request):
            self.received.append((request.raw_path, dict(request.headers)))
            if request.path == '/ws':
                ws = web.WebSocketResponse(protocols=['echo'])
                await ws.prepare(request)
                async for msg in ws:
                    if msg.type == WSMsgType.TEXT:
                        await ws.send_str(msg.data)
                    elif msg.type == WSMsgType.BINARY:
                        await ws.send_bytes(msg.data)
                return ws
            if request.path == '/redirect':
                return web.Response(status=302, headers={'Location': '/next?q=1'})
            if request.path == '/events':
                out = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
                await out.prepare(request)
                await out.write(b'data: hello\n\n')
                await asyncio.sleep(.1)
                await out.write(b'data: bye\n\n')
                return out
            if request.path == '/binary':
                return web.Response(body=bytes(range(256)), headers={'Content-Type': 'application/octet-stream'})
            if request.path == '/css':
                return web.Response(text='body{background:url(/img.png)}', content_type='text/css')
            if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                return web.Response(body=await request.read(), status=201)
            return web.Response(text='<html><head></head><body><a href="/next">next</a><script src="/app.js"></script></body></html>',
                                content_type='text/html', headers={'Set-Cookie': 'app=one; Path=/; HttpOnly'})

        target_app = web.Application()
        target_app.router.add_route('*', '/{path:.*}', target)
        self.target = TestServer(target_app)
        await self.target.start_server()
        self.addAsyncCleanup(self.target.close)
        self.port = self.target.port
        self.backend = SimpleNamespace(PORT=59999,
            request_authed=lambda r: r.headers.get('Cookie', '').startswith('tmux_web_token=test'),
            node_secret=lambda: 'test-secret')
        self.proxy = TestServer(frontend.create_app(self.backend))
        await self.proxy.start_server()
        self.addAsyncCleanup(self.proxy.close)
        self.client = ClientSession(headers={'Cookie': 'tmux_web_token=test; app=one'})
        self.addAsyncCleanup(self.client.close)
        self.prefix = f'/port/{self.port}/'

    def url(self, path=''):
        return self.proxy.make_url(self.prefix + path)

    async def test_html_paths_and_cookie_isolation(self):
        async with self.client.get(self.url()) as r:
            text = await r.text()
            self.assertEqual(r.status, 200)
            self.assertIn('data-tmux-port-proxy', text)
            self.assertIn(f'href="{self.prefix}next"', text)
            self.assertIn(f'src="{self.prefix}app.js"', text)
            self.assertIn('Path=' + self.prefix, r.headers['Set-Cookie'])
        self.assertEqual(self.received[-1][1]['Cookie'], 'app=one')
        self.assertEqual(self.received[-1][1]['Host'], f'127.0.0.1:{self.port}')

    async def test_methods_binary_query_and_redirect(self):
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            async with self.client.request(method, self.url('echo?a=%2F&b=2'), data=b'body\x00') as r:
                self.assertEqual(r.status, 201)
                self.assertEqual(await r.read(), b'body\x00')
                self.assertEqual(self.received[-1][0], '/echo?a=/&b=2')  # aiohttp URL normalization
        async with self.client.get(self.url('binary')) as r:
            self.assertEqual(await r.read(), bytes(range(256)))
        async with self.client.get(self.url('redirect'), allow_redirects=False) as r:
            self.assertEqual(r.headers['Location'], self.prefix + 'next?q=1')
        async with self.client.get(self.url('css')) as r:
            self.assertIn('url(' + self.prefix + 'img.png)', await r.text())

    async def test_websocket_text_binary_and_subprotocol(self):
        async with self.client.ws_connect(self.url('ws'), protocols=['echo']) as ws:
            self.assertEqual(ws.protocol, 'echo')
            await ws.send_str('hello')
            self.assertEqual((await ws.receive()).data, 'hello')
            await ws.send_bytes(b'\x00\xff')
            self.assertEqual((await ws.receive()).data, b'\x00\xff')

    async def test_streaming_sse(self):
        async with self.client.get(self.url('events')) as r:
            self.assertEqual(await asyncio.wait_for(r.content.readline(), 1), b'data: hello\n')
            self.assertIn(b'data: bye', await r.read())

    async def test_validation_auth_and_unavailable_port(self):
        async with ClientSession() as anonymous:
            async with anonymous.get(self.url()) as r:
                self.assertEqual(r.status, 401)
            with self.assertRaises(Exception):
                await anonymous.ws_connect(self.url('ws'))
        for port in ('0', '65536', '-1', 'abc', '59999'):
            async with self.client.get(self.proxy.make_url(f'/port/{port}/')) as r:
                self.assertEqual(r.status, 400)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            unused = sock.getsockname()[1]
        async with self.client.get(self.proxy.make_url(f'/port/{unused}/')) as r:
            self.assertEqual(r.status, 502)

    async def test_existing_api_and_node_websocket_adapter(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        secret_patch = patch.object(server, 'NODE_SECRET_FILE', os.path.join(tmp.name, '.node-secret'))
        secret_patch.start()
        self.addCleanup(secret_patch.stop)
        hub = TestServer(frontend.create_app(server))
        await hub.start_server()
        try:
            headers = {'Authorization': 'Bearer ' + server.node_secret()}
            async with self.client.get(hub.make_url('/api/sessions'), headers=headers) as r:
                self.assertEqual(r.status, 200)
                self.assertIsInstance(await r.json(), list)
            url = hub.make_url('/ws-node?name=proxy-test&token=' + server.node_secret())
            async with self.client.ws_connect(url) as ws:
                await ws.send_json({'type': 'hello', 'sessions': []})
                reply = await ws.receive_json()
                self.assertEqual(reply['type'], 'hello-ok')
                self.assertIn('proxy-test', server.NODES)
            await asyncio.sleep(.02)
            self.assertNotIn('proxy-test', server.NODES)
        finally:
            await hub.close()


    async def test_node_bearer_header_authentication(self):
        secret = secrets.token_urlsafe(24)
        with patch.object(server, 'node_secret', return_value=secret):
            hub = TestServer(frontend.create_app(server))
            await hub.start_server()
            try:
                url = hub.make_url('/ws-node?name=bearer-test')
                async with self.client.ws_connect(url, headers={'Authorization': 'Bearer ' + secret}) as ws:
                    await ws.send_json({'type': 'hello', 'sessions': []})
                    self.assertEqual((await ws.receive_json())['type'], 'hello-ok')
                    self.assertIn('bearer-test', server.NODES)
                await asyncio.sleep(.02)
                self.assertNotIn('bearer-test', server.NODES)
                with self.assertRaises(Exception):
                    await self.client.ws_connect(url, headers={'Authorization': 'Bearer invalid'})
            finally:
                await hub.close()


    async def test_noise_node_authenticates_before_registration(self):
        secret = secrets.token_urlsafe(24)
        with patch.object(server, 'node_secret', return_value=secret), patch.object(server, 'NODES', {}):
            hub = TestServer(frontend.create_app(server))
            await hub.start_server()
            try:
                url = str(hub.make_url('/ws-node?v=2')).replace('http://', 'ws://', 1)
                raw = await node.Ws.connect(url, allow_insecure_ws=True)
                channel = await node.NoiseChannel.establish(node.WsRaw(raw), secret, initiator=True)
                self.assertEqual(server.NODES, {})
                await channel.send(json.dumps({'type': 'hello', 'version': 2,
                                               'name': 'encrypted-test', 'sessions': []}))
                self.assertEqual(json.loads(await channel.recv())['type'], 'hello-ok')
                self.assertIn('encrypted-test', server.NODES)
                # Exercise maximum-size Noise records through the real aiohttp
                # parser, whose WebSocket size limit is exclusive.
                reply = asyncio.get_running_loop().create_future()
                server.NODES['encrypted-test'].pending[123] = reply
                large = {'type': 'reply', 'id': 123, 'payload': 'x' * 131072}
                await channel.send(json.dumps(large))
                self.assertEqual(await asyncio.wait_for(reply, 3), large)
                await server.NODES['encrypted-test'].send_json(large)
                self.assertEqual(json.loads(await channel.recv()), large)
                await channel.close()
                await asyncio.sleep(.02)
                self.assertEqual(server.NODES, {})
                raw = await node.Ws.connect(url, allow_insecure_ws=True)
                with self.assertRaises(node.NoiseError):
                    await node.NoiseChannel.establish(node.WsRaw(raw), secrets.token_urlsafe(24), initiator=True)
                self.assertEqual(server.NODES, {})
                with self.assertRaises(Exception):
                    await self.client.ws_connect(hub.make_url('/ws-node?v=2&token=invalid'))
            finally:
                await hub.close()


    async def test_truncated_node_download_is_an_error(self):
        remote = SimpleNamespace(
            file_get=AsyncMock(return_value=({'ok': True, 'size': 100, 'name': 'data.bin'}, 1, None)),
            file_collect=AsyncMock(return_value=(b'truncated', True)))
        with patch.object(server, 'NODES', {'test': remote}), patch.object(server, 'request_authed', return_value=True):
            hub = TestServer(frontend.create_app(server))
            await hub.start_server()
            try:
                async with self.client.get(hub.make_url('/api/download?node=test&path=/tmp/data.bin')) as response:
                    self.assertEqual(response.status, 502)
                    self.assertIn('incomplete', await response.text())
            finally:
                await hub.close()


if __name__ == '__main__':
    unittest.main()
