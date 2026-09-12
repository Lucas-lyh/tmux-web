import asyncio
import json
import secrets
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiohttp import ClientSession
from aiohttp.test_utils import TestServer
from websockets.asyncio.client import connect

import node
import server
from http_frontend import create_app
from hub.credentials import NodeCredentials


class CredentialStoreTests(unittest.TestCase):
    def test_expiry_one_use_scope_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = [1000]
            store = NodeCredentials(Path(tmp) / 'credentials.json', clock=lambda: now[0])
            token = store.issue(ttl=10)
            selector = token.rsplit('.', 1)[0]
            self.assertEqual(store.lookup(selector), token)
            key, permanent = store.prepare(selector, 'fixture', token)
            with self.assertRaises(ValueError):
                store.prepare(selector, 'fixture', token)
            store.complete(key)
            with self.assertRaises(ValueError):
                store.lookup(selector)
            with self.assertRaises(ValueError):
                store.prepare('twn.' + key, 'different-name', permanent)
            restored = NodeCredentials(store.path, clock=lambda: now[0])
            self.assertEqual(restored.lookup('twn.' + key), permanent)
            self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(permanent, json.dumps(store.public_records()))
            restored.revoke(key)
            with self.assertRaises(ValueError):
                restored.lookup('twn.' + key)
            expiring = restored.issue(ttl=10)
            now[0] += 11
            with self.assertRaises(ValueError):
                restored.lookup(expiring.rsplit('.', 1)[0])


class SecurityLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        values = {'AUTH_FILE': str(self.root / 'auth.json'),
                  'TOKEN_FILE': str(self.root / 'tokens.json'),
                  'NODE_SECRET_FILE': str(self.root / 'master'),
                  'NODE_CREDENTIALS': NodeCredentials(self.root / 'credentials.json'),
                  '_AUTH': None, '_TOKENS': {}, 'NODES': {}, '_REGISTERING_NAMES': set(),
                  '_BROWSER_CONNECTIONS': {}}
        for name, value in values.items():
            p = patch.object(server, name, value)
            p.start(); self.addCleanup(p.stop)
        env = patch.dict(server.os.environ, {'TMUX_WEB_PASSWORD': 'fixture-password'})
        env.start(); self.addCleanup(env.stop)
        self.hub = TestServer(create_app(server))
        await self.hub.start_server()
        self.addAsyncCleanup(self.hub.close)
        self.client = ClientSession()
        self.addAsyncCleanup(self.client.close)
        self.auth = {'Authorization': 'Bearer ' + server.node_secret()}

    async def open_channel(self, token, name='fixture', ack=True):
        selector = token.rsplit('.', 1)[0]
        endpoint = str(self.hub.make_url('/ws-node?v=2&key=' + selector)).replace('http:', 'ws:')
        raw = await connect(endpoint)
        self.addAsyncCleanup(raw.close)
        channel = await node.NoiseChannel.establish(raw, token, True)
        await channel.send(json.dumps({'type': 'hello', 'version': 2, 'name': name,
                                      'capabilities': ['credential-v1'], 'sessions': []}))
        reply = json.loads(await channel.recv())
        if ack and reply.get('credential'):
            await channel.send(json.dumps({'type': 'credential-ack'}))
        return channel, reply

    async def wait_registered(self, name='fixture', present=True):
        async def wait():
            while (name in server.NODES) != present:
                await asyncio.sleep(.01)
        await asyncio.wait_for(wait(), 3)

    async def test_enrollment_reconnect_and_revocation_never_grant_admin(self):
        async with self.client.post(self.hub.make_url('/api/node-enroll'), headers=self.auth, json={}) as r:
            self.assertEqual(r.status, 200)
            grant = await r.json()
        channel, reply = await self.open_channel(grant['token'])
        await self.wait_registered()
        permanent = reply['credential']
        key = permanent.split('.')[1]
        for credential in (grant['token'], permanent):
            async with self.client.get(self.hub.make_url('/api/nodes'),
                    headers={'Authorization': 'Bearer ' + credential}) as r:
                self.assertEqual(r.status, 401)
        async with self.client.get(self.hub.make_url('/api/nodes'), headers=self.auth) as r:
            info = await r.json()
            self.assertNotIn('secret', info)
            self.assertEqual(info['nodes'][0]['credential_id'], key)
        with self.assertRaises(ValueError):
            server.NODE_CREDENTIALS.lookup(grant['token'].rsplit('.', 1)[0])
        await channel.close()
        await self.wait_registered(present=False)
        channel, reply = await self.open_channel(permanent)
        self.assertNotIn('credential', reply)
        await self.wait_registered()
        async with self.client.post(self.hub.make_url('/api/node-revoke'), headers=self.auth, json={'id': key}) as r:
            self.assertEqual(r.status, 200)
        await self.wait_registered(present=False)
        with self.assertRaises(ValueError):
            server.NODE_CREDENTIALS.lookup('twn.' + key)

    async def test_saved_credential_recovers_lost_acknowledgement(self):
        token = server.NODE_CREDENTIALS.issue()
        channel, reply = await self.open_channel(token, ack=False)
        await channel.close()
        for _ in range(100):
            if not server._REGISTERING_NAMES:
                break
            await asyncio.sleep(.01)
        channel, _ = await self.open_channel(reply['credential'])
        await self.wait_registered()
        with self.assertRaises(ValueError):
            server.NODE_CREDENTIALS.lookup(token.rsplit('.', 1)[0])

    async def test_password_change_revokes_old_tokens_and_reissues_current_cookie(self):
        server.check_password('fixture-password')
        old = server.new_token()
        browser = SimpleNamespace(close=AsyncMock())
        server._BROWSER_CONNECTIONS[1] = browser
        cookie = {'Cookie': server.COOKIE_NAME + '=' + old}
        async with self.client.post(self.hub.make_url('/api/passwd'), headers=cookie,
                json={'old': 'fixture-password', 'new': 'fixture-replacement'}) as r:
            self.assertEqual(r.status, 200)
            self.assertIn('Set-Cookie', r.headers)
            replacement = r.cookies[server.COOKIE_NAME].value
        browser.close.assert_awaited_once()
        self.assertNotEqual(old, replacement)
        self.assertFalse(server.request_authed(SimpleNamespace(headers=cookie)))
        self.assertNotIn(old, server._load_tokens())
        self.assertIn(replacement, server._load_tokens())
        self.assertTrue(server.request_authed(SimpleNamespace(headers=self.auth)))

    async def test_failed_token_file_write_cannot_resurrect_revoked_login(self):
        server.check_password('fixture-password')
        old = server.new_token()
        with patch.object(server, '_save_tokens', side_effect=OSError('fixture failure')):
            with self.assertRaises(OSError):
                server.set_password('fixture-replacement')
        server._AUTH = None
        self.assertTrue(server.check_password('fixture-replacement'))
        self.assertNotIn(old, server._load_tokens())

    async def test_legacy_login_tokens_survive_normal_upgrade(self):
        server.check_password('fixture-password')
        Path(server.TOKEN_FILE).write_text(json.dumps({'historical-token': time.time() + 600}))
        self.assertIn('historical-token', server._load_tokens())

    async def test_cancelled_revocation_still_closes_only_its_node_connection(self):
        entered, release = threading.Event(), threading.Event()
        socket, unrelated = SimpleNamespace(close=AsyncMock()), SimpleNamespace(close=AsyncMock())
        grant = server.NODE_CREDENTIALS.issue()
        key, _ = server.NODE_CREDENTIALS.prepare(grant.rsplit('.', 1)[0], 'fixture', grant)
        server.NODE_CREDENTIALS.complete(key)
        original_revoke = server.NODE_CREDENTIALS.revoke
        def revoke(key):
            entered.set()
            if not release.wait(2):
                raise AssertionError('fixture worker not released')
            return original_revoke(key)
        with patch.object(server.NODE_CREDENTIALS, 'revoke', side_effect=revoke):
            server.NODES.update(target=SimpleNamespace(credential_id=key, ws=socket),
                                other=SimpleNamespace(credential_id='other-key', ws=unrelated))
            task = asyncio.create_task(server.revoke_node_credential(key))
            for _ in range(100):
                if entered.is_set():
                    break
                await asyncio.sleep(.005)
            task.cancel()
            await asyncio.sleep(0)
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        socket.close.assert_awaited_once()
        unrelated.close.assert_not_called()

    async def test_invalid_bearer_cannot_exempt_cookie_websocket_from_revocation(self):
        server.check_password('fixture-password')
        token = server.new_token()
        ws = SimpleNamespace(request=SimpleNamespace(path='/ws?session=fixture', headers={
            'Cookie': server.COOKIE_NAME + '=' + token, 'Authorization': 'Bearer invalid'}), close=AsyncMock())
        async def handle(socket):
            self.assertIn(id(socket), server._BROWSER_CONNECTIONS)
            await server.revoke_browser_connections()
        with patch.object(server, '_handle_ws', side_effect=handle):
            await server.handle_ws(ws)
        ws.close.assert_awaited_once()
        self.assertFalse(server._BROWSER_CONNECTIONS)

    async def test_password_change_during_websocket_prepare_is_rechecked(self):
        server.check_password('fixture-password')
        token = server.new_token()
        ws = SimpleNamespace(request=SimpleNamespace(path='/ws-upload', headers={
            'Cookie': server.COOKIE_NAME + '=' + token}), close=AsyncMock())
        self.assertTrue(server.request_authed(ws.request))
        server.set_password('fixture-replacement')
        with patch.object(server, '_handle_ws', new_callable=AsyncMock) as handle:
            await server.handle_ws(ws)
            handle.assert_not_awaited()
        ws.close.assert_awaited_once_with(4001, 'login expired')

    async def test_password_commit_closes_old_sockets_when_token_persistence_fails(self):
        server.check_password('fixture-password')
        socket = SimpleNamespace(close=AsyncMock())
        server._BROWSER_CONNECTIONS[1] = socket
        request = SimpleNamespace(path='/api/passwd?old=fixture-password&new=fixture-replacement',
                                  headers=self.auth, method='POST')
        with patch.object(server, '_save_tokens', side_effect=OSError('fixture disk failure')):
            with self.assertRaises(OSError):
                await server.process_request(SimpleNamespace(), request)
        self.assertTrue(server.check_password('fixture-replacement'))
        socket.close.assert_awaited_once()

    async def test_directory_sync_failure_does_not_reauthorize_a_revoked_key(self):
        token = server.NODE_CREDENTIALS.issue()
        key, permanent = server.NODE_CREDENTIALS.prepare(token.rsplit('.', 1)[0], 'fixture', token)
        server.NODE_CREDENTIALS.complete(key)
        socket = SimpleNamespace(close=AsyncMock())
        server.NODES['fixture'] = SimpleNamespace(credential_id=key, ws=socket)
        real_sync = server.os.fsync
        def failing_sync(fd):
            if stat.S_ISDIR(server.os.fstat(fd).st_mode):
                raise OSError('fixture directory fsync failure after rename')
            return real_sync(fd)
        with patch('hub.storage.os.fsync', side_effect=failing_sync):
            with self.assertRaises(OSError):
                await server.revoke_node_credential(key)
        self.assertFalse(server.NODE_CREDENTIALS.active(key))
        with self.assertRaises(ValueError):
            server.NODE_CREDENTIALS.lookup('twn.' + key)
        socket.close.assert_awaited_once()


if __name__ == '__main__':
    unittest.main()
