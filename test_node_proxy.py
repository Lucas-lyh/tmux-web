"""Environment routing and HTTP CONNECT integration, without external networking."""
import asyncio
import base64
import hashlib
import os
import unittest
from unittest.mock import AsyncMock, Mock, patch

import node


class ProxyEnvironmentTests(unittest.TestCase):
    def resolve(self, env, url="ws://hub.example:59999/ws-node"):
        with patch.dict(os.environ, env, clear=True):
            return node.node_proxy(node.validate_server_url(url))

    def test_environment_precedence_and_uppercase(self):
        for env, expected in [
            ({}, None),
            ({"HTTP_PROXY": "http://upper:3128"}, "upper"),
            ({"http_proxy": "http://lower:3128", "HTTP_PROXY": "http://upper"}, "lower"),
            ({"ALL_PROXY": "http://fallback"}, "fallback"),
            ({"http_proxy": "http://first", "all_proxy": "http://fallback"}, "first"),
            ({"https_proxy": "http://unused"}, None),
        ]:
            with self.subTest(env=env):
                result = self.resolve(env)
                self.assertEqual(result.hostname if result else None, expected)

    def test_no_proxy(self):
        for bypass in ("*", "hub.example", ".example", "hub.example:59999"):
            for key in ("no_proxy", "NO_PROXY"):
                self.assertIsNone(self.resolve({"http_proxy": "http://proxy", key: bypass}))
        self.assertIsNotNone(self.resolve({"http_proxy": "http://proxy", "no_proxy": "other.example"}))
        self.assertIsNone(self.resolve({"http_proxy": "http://proxy", "no_proxy": "::1"},
                                       "ws://[::1]:59999/ws-node"))

    def test_invalid_proxy_is_safe_and_not_silently_bypassed(self):
        for value in ("socks5://secret@proxy:1080", "https://proxy", "http://proxy:bad",
                      "http://proxy:0", "http://proxy/path", "http://proxy\r\nsecret"):
            with self.subTest(value=value), self.assertRaises(node.ProxyError) as caught:
                self.resolve({"http_proxy": value})
            self.assertNotIn("secret", str(caught.exception))


class ProxyConnectTests(unittest.IsolatedAsyncioTestCase):
    async def test_bad_responses_and_timeouts(self):
        target = node.validate_server_url("ws://hub.example:59999/ws-node")
        proxy = node.urllib.parse.urlsplit("http://proxy:3128")
        for response, error, message in [
            (b"secret-invalid-status\r\n\r\n", None, "invalid proxy CONNECT status"),
            (None, asyncio.TimeoutError(), "proxy CONNECT timed out"),
            (None, asyncio.IncompleteReadError(b"secret", 10), "incomplete"),
            (None, asyncio.LimitOverrunError("secret", 65536), "incomplete"),
        ]:
            reader = Mock()
            reader.readuntil = AsyncMock(return_value=response, side_effect=error)
            writer = Mock()
            writer.drain = AsyncMock()
            with self.subTest(message=message), self.assertRaisesRegex(node.ProxyError, message) as caught:
                await node.proxy_connect(reader, writer, target, proxy)
            self.assertNotIn("secret", str(caught.exception))

    async def run_proxy(self, *, status=200, auth=False, bypass=False):
        requests = []
        completed = asyncio.get_running_loop().create_future()

        async def handle(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                requests.append(request)
                if not bypass:
                    writer.write(f"HTTP/1.1 {status} secret-reflected-value\r\n\r\n".encode())
                    await writer.drain()
                    if status != 200:
                        self.assertEqual(await reader.read(), b"")
                        return
                    request = await reader.readuntil(b"\r\n\r\n")
                    requests.append(request)
                headers = dict(line.split(b":", 1) for line in request.split(b"\r\n")[1:] if line)
                accept = base64.b64encode(hashlib.sha1(
                    headers[b"Sec-WebSocket-Key"].strip() +
                    b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                             b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept +
                             b"\r\n\r\n\x81\x02ok")
                await writer.drain()
                await reader.read()
            except Exception as exc:
                completed.set_exception(exc)
            finally:
                writer.close()
                await writer.wait_closed()
                if not completed.done():
                    completed.set_result(None)

        listener = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.addAsyncCleanup(listener.wait_closed)
        self.addCleanup(listener.close)
        port = listener.sockets[0].getsockname()[1]
        credentials = "u%40ser:p%3Ass@" if auth else ""
        env = {"http_proxy": f"http://{credentials}127.0.0.1:{port}"}
        # This destination cannot resolve: the proxy must perform destination DNS.
        url = "ws://hub.invalid:59999/ws-node?v=2"
        if bypass:
            env["no_proxy"] = "127.0.0.1"
            url = f"ws://127.0.0.1:{port}/ws-node?v=2"
        with patch.dict(os.environ, env, clear=True):
            if status != 200:
                with self.assertRaisesRegex(node.ProxyError, f"HTTP {status}") as caught:
                    await asyncio.wait_for(node.Ws.connect(url), 3)
                self.assertNotIn("secret-reflected-value", str(caught.exception))
            else:
                ws = await asyncio.wait_for(node.Ws.connect(url), 3)
                try:
                    self.assertEqual(await asyncio.wait_for(ws.recv(), 3), (1, b"ok"))
                finally:
                    await ws.close()
        await asyncio.wait_for(completed, 3)
        return requests

    async def test_connect_and_websocket_data(self):
        requests = await self.run_proxy(auth=True)
        self.assertIn(b"CONNECT hub.invalid:59999 HTTP/1.1\r\n", requests[0])
        self.assertIn(b"Proxy-Authorization: Basic " + base64.b64encode(b"u@ser:p:ss"), requests[0])
        self.assertTrue(requests[1].startswith(b"GET /ws-node?v=2 HTTP/1.1"))
        self.assertNotIn(b"Proxy-Authorization", requests[1])

    async def test_rejections_close_socket(self):
        for status in (403, 407, 502):
            with self.subTest(status=status):
                await self.run_proxy(status=status)

    async def test_no_proxy_connects_directly(self):
        requests = await self.run_proxy(bypass=True)
        self.assertEqual(len(requests), 1)
        self.assertTrue(requests[0].startswith(b"GET "))


if __name__ == "__main__":
    unittest.main()
