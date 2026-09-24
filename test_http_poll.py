"""HTTP-only encrypted node registration through an Upgrade-stripping proxy."""
import asyncio
import os
import unittest
from unittest.mock import patch

from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer

import node
import server
from hub.http_poll import install


class HttpPollTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.secret = patch.object(server, 'node_secret', return_value='poll-test-secret')
        self.secret.start()
        self.addCleanup(self.secret.stop)
        app = web.Application()
        install(app, server)
        self.hub = TestServer(app)
        await self.hub.start_server()
        self.addAsyncCleanup(self.hub.close)
        self.client = ClientSession()
        self.addAsyncCleanup(self.client.close)
        self.requests = []

        async def forward(request):
            self.requests.append((request.method, request.raw_path, dict(request.headers)))
            self.assertEqual(request.method, 'POST')
            self.assertNotIn('Upgrade', request.headers)
            url = str(self.hub.make_url(request.path_qs))
            async with self.client.post(url, data=await request.read()) as response:
                return web.Response(status=response.status, body=await response.read(), headers={'Cache-Control': 'no-store'})
        proxy = web.Application()
        proxy.router.add_route('*', '/{tail:.*}', forward)
        self.proxy = TestServer(proxy)
        await self.proxy.start_server()
        self.addAsyncCleanup(self.proxy.close)
        self.env = patch.dict(os.environ, {'http_proxy': str(self.proxy.make_url('')), 'no_proxy': ''}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.url = 'ws://unresolvable.example:59999/ws-node?v=2'

    async def test_encrypted_registration_and_binary_records_through_proxy(self):
        raw = await node.HttpPollRaw.connect(self.url)
        channel = await node.NoiseChannel.establish(raw, 'poll-test-secret', True)
        self.addAsyncCleanup(channel.close)
        await channel.send('{"type":"hello","version":2,"name":"http-poll-test","sessions":[]}')
        self.assertIn('hello-ok', await channel.recv())
        self.assertIn('http-poll-test', server.NODES)
        conn = server.NODES['http-poll-test']
        payload = b'\x00' * 100000
        sending = asyncio.create_task(conn.ws.send(payload))
        self.assertEqual(await channel.recv(), payload)
        await sending
        await channel.close()
        for _ in range(50):
            if 'http-poll-test' not in server.NODES:
                break
            await asyncio.sleep(.01)
        self.assertNotIn('http-poll-test', server.NODES)
        self.assertTrue(all(path.startswith('http://unresolvable.example:59999/node-http/') for _, path, _ in self.requests))

    async def test_wrong_secret_cannot_register(self):
        raw = await node.HttpPollRaw.connect(self.url)
        with self.assertRaises(node.NoiseError):
            await node.NoiseChannel.establish(raw, 'wrong-secret', True)
        self.assertNotIn('http-poll-test', server.NODES)

    async def test_duplicate_send_closes_channel(self):
        raw = await node.HttpPollRaw.connect(self.url)
        channel = await node.NoiseChannel.establish(raw, 'poll-test-secret', True)
        self.addAsyncCleanup(channel.close)
        await channel.send('{"type":"hello","version":2,"name":"http-poll-test","sessions":[]}')
        await channel.recv()
        with self.assertRaisesRegex(ConnectionError, 'HTTP 409'):
            await asyncio.to_thread(raw._request, 'send', b'x' * 48, raw.sequences['send'] - 1)

    async def test_receive_waits_until_server_has_data(self):
        raw = await node.HttpPollRaw.connect(self.url)
        channel = await node.NoiseChannel.establish(raw, 'poll-test-secret', True)
        self.addAsyncCleanup(channel.close)
        await channel.send('{"type":"hello","version":2,"name":"http-poll-test","sessions":[]}')
        await channel.recv()
        receive = asyncio.create_task(channel.recv())
        try:
            await asyncio.sleep(.05)
            self.assertFalse(receive.done())
            await server.NODES['http-poll-test'].ws.send('wake')
            self.assertEqual(await asyncio.wait_for(receive, 2), 'wake')
        finally:
            receive.cancel()
            await asyncio.gather(receive, return_exceptions=True)

    async def test_unknown_channel_and_oversized_body(self):
        async with self.client.post(self.hub.make_url('/node-http/recv?sid=missing&seq=0')) as response:
            self.assertEqual(response.status, 410)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        async with self.client.post(self.hub.make_url('/node-http/open'), data=b'x' * 65536) as response:
            self.assertEqual(response.status, 413)
