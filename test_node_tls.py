"""Exercise node transport against local TLS peers with disposable certificates."""

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, call, patch
import urllib.parse

import node
import server


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


async def read_client_frame(reader):
    """Decode a client frame independently of node.Ws, including its mask."""
    first, second = await reader.readexactly(2)
    length = second & 0x7f
    if length == 126:
        length = int.from_bytes(await reader.readexactly(2), "big")
    elif length == 127:
        length = int.from_bytes(await reader.readexactly(8), "big")
    masked = bool(second & 0x80)
    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length)
    if masked:
        payload = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
    return first & 0x0f, payload, masked


async def send_server_frame(writer, opcode, payload):
    length = len(payload)
    if length < 126:
        header = bytes([0x80 | opcode, length])
    elif length < 65536:
        header = bytes([0x80 | opcode, 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x80 | opcode, 127]) + struct.pack("!Q", length)
    writer.write(header + payload)
    await writer.drain()


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed for temporary TLS certificates")
class NodeTLSTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        temporary = tempfile.TemporaryDirectory(prefix="tmux-web-tls-test-")
        cls.addClassCleanup(temporary.cleanup)
        cls.tls_dir = Path(temporary.name)
        cls.ca = cls.tls_dir / "ca.pem"
        cls.cert = cls.tls_dir / "server.pem"
        cls.key = cls.tls_dir / "server.key"
        extensions = cls.tls_dir / "server.ext"
        extensions.write_text(
            "subjectAltName=DNS:localhost\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
        )
        commands = [
            ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-days", "1", "-subj", "/CN=tmux-web disposable test CA",
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-addext", "subjectKeyIdentifier=hash",
             "-keyout", "ca.key", "-out", str(cls.ca)],
            ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-subj", "/CN=localhost", "-keyout", str(cls.key), "-out", "server.csr"],
            ["x509", "-req", "-in", "server.csr", "-CA", str(cls.ca), "-CAkey", "ca.key",
             "-set_serial", "1", "-days", "1", "-extfile", str(extensions), "-out", str(cls.cert)],
        ]
        for command in commands:
            subprocess.run(["openssl", *command], cwd=cls.tls_dir,
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    async def asyncSetUp(self):
        self.requests = []
        self.peers = set()
        self.tasks = set()
        self.exchanges = []
        self.servers = []
        self.clients = []
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.server_context.load_cert_chain(self.cert, self.key)
        self.client_context = ssl.create_default_context(cafile=str(self.ca))
        self.client_context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Match Python 3.13's stricter default certificate checks on older Python too.
        self.client_context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
        self.expect_tls_rejection = False
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()

        def exception_handler(event_loop, context):
            # Certificate rejection disconnects the server before its accept callback.
            if (self.expect_tls_rejection
                    and context.get("message") == "Error on transport creation for incoming connection"
                    and isinstance(context.get("exception"), (ssl.SSLError, ConnectionResetError))):
                return
            if previous_handler:
                previous_handler(event_loop, context)
            else:
                event_loop.default_exception_handler(context)

        loop.set_exception_handler(exception_handler)
        self.addCleanup(loop.set_exception_handler, previous_handler)
        self.addAsyncCleanup(self.close_connections)

    async def close_connections(self):
        for ws in self.clients:
            await ws.close()
        for listener in self.servers:
            listener.close()
            await listener.wait_closed()
        for peer in list(self.peers):
            peer.close()
        if self.tasks:
            pending = list(self.tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        for exchange in self.exchanges:
            if exchange.done() and not exchange.cancelled():
                # Retrieve exceptions even if a failed client never reaches the exchange.
                error = exchange.exception()
                if error is not None:
                    raise error

    async def start_peer(self, *, on_ws=None, secure=True, bad_accept=False):
        completed = asyncio.get_running_loop().create_future()
        self.exchanges.append(completed)

        async def handle(reader, writer):
            self.peers.add(writer)
            try:
                request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
                request_line, *header_lines = request.decode("latin1").split("\r\n")
                headers = dict(line.split(":", 1) for line in header_lines if line)
                headers = {key.lower(): value.strip() for key, value in headers.items()}
                self.requests.append((request_line, headers))
                accept = base64.b64encode(hashlib.sha1(
                    (headers["sec-websocket-key"] + WS_GUID).encode()).digest()).decode()
                if bad_accept:
                    accept = "incorrect-websocket-accept"
                writer.write((
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode())
                await writer.drain()
                result = await on_ws(reader, writer) if on_ws else await reader.read()
                if not completed.done():
                    completed.set_result(result)
            except asyncio.CancelledError:
                if not completed.done():
                    completed.cancel()
                raise
            except Exception as exc:
                if not completed.done():
                    completed.set_exception(exc)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, ssl.SSLError):
                    pass
                self.peers.discard(writer)

        def connected(reader, writer):
            task = asyncio.create_task(handle(reader, writer))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

        listener = await asyncio.start_server(
            connected, "127.0.0.1", 0, ssl=self.server_context if secure else None)
        self.servers.append(listener)
        port = listener.sockets[0].getsockname()[1]
        scheme = "wss" if secure else "ws"
        return f"{scheme}://localhost:{port}/ws-node", completed

    async def connect(self, url, **kwargs):
        ws = await asyncio.wait_for(node.Ws.connect(url, **kwargs), 5)
        self.clients.append(ws)
        return ws

    async def test_trusted_ca_encrypts_handshake_and_keeps_token_out_of_url(self):
        url, _ = await self.start_peer()
        token = secrets.token_urlsafe(24)
        ws = await self.connect(url + "?name=lab", token=token,
                                ssl_context=self.client_context)
        self.assertIn(ws.w.get_extra_info("ssl_object").version(), ("TLSv1.2", "TLSv1.3"))
        self.assertEqual(len(self.requests), 1)
        line, headers = self.requests[0]
        self.assertEqual(line, "GET /ws-node?name=lab HTTP/1.1")
        self.assertNotIn(token, line)
        self.assertEqual(headers["authorization"], f"Bearer {token}")

    async def test_untrusted_certificate_is_rejected(self):
        self.expect_tls_rejection = True
        url, _ = await self.start_peer()
        # No explicit CA: the system trust store must not trust the temporary CA.
        with self.assertRaises(ssl.SSLCertVerificationError):
            await self.connect(url, token="temporary-test-token")
        self.assertEqual(self.requests, [])

    async def test_trusted_certificate_for_wrong_hostname_is_rejected(self):
        self.expect_tls_rejection = True
        url, _ = await self.start_peer()
        with self.assertRaises(ssl.SSLCertVerificationError):
            await self.connect(url.replace("localhost", "127.0.0.1"),
                               token="temporary-test-token", ssl_context=self.client_context)
        self.assertEqual(self.requests, [])

    async def test_plain_websocket_requires_explicit_opt_in_before_network(self):
        with patch.object(node.asyncio, "open_connection", new_callable=AsyncMock) as connect:
            with self.assertRaises(ValueError):
                await node.Ws.connect("ws://localhost:12345/ws-node", token="temporary-test-token")
            connect.assert_not_called()

    async def test_explicit_plain_websocket_compatibility(self):
        url, _ = await self.start_peer(secure=False)
        ws = await self.connect(url, token="temporary-test-token", allow_insecure_ws=True)
        self.assertIsNone(ws.w.get_extra_info("ssl_object"))
        self.assertEqual(self.requests[0][1]["authorization"], "Bearer temporary-test-token")
        self.assertNotIn("token=", self.requests[0][0])

    async def test_disabled_certificate_verification_is_rejected_before_network(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with patch.object(node.asyncio, "open_connection", new_callable=AsyncMock) as connect:
            with self.assertRaises(ValueError):
                await node.Ws.connect("wss://localhost/ws-node", ssl_context=context)
            connect.assert_not_called()

    async def test_token_cannot_inject_handshake_headers(self):
        with patch.object(node.asyncio, "open_connection", new_callable=AsyncMock) as connect:
            with self.assertRaises(ValueError):
                await node.Ws.connect("wss://localhost/ws-node", token="test\r\nInjected: header")
            connect.assert_not_called()

    async def test_agent_forwards_transport_policy_without_token_in_url(self):
        token = secrets.token_urlsafe(24)
        for scheme, insecure in (("wss", False), ("ws", True)):
            with self.subTest(scheme=scheme):
                agent = node.Agent(f"{scheme}://localhost/ws-node?existing=value", token, "lab 测试",
                                   ssl_context=self.client_context, allow_insecure_ws=insecure)
                with patch.object(node.Ws, "connect", new_callable=AsyncMock,
                                  side_effect=asyncio.CancelledError) as connect:
                    with self.assertRaises(asyncio.CancelledError):
                        await agent.run()
                    connect.assert_awaited_once()
                    arguments = connect.call_args
                url = arguments.args[0]
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                self.assertEqual(query, {"existing": ["value"], "name": ["lab 测试"]})
                self.assertNotIn(token, url)
                self.assertEqual(arguments.kwargs["token"], token)
                self.assertIs(arguments.kwargs["ssl_context"], self.client_context)
                self.assertEqual(arguments.kwargs["allow_insecure_ws"], insecure)

    async def test_incorrect_websocket_accept_is_rejected(self):
        url, completed = await self.start_peer(bad_accept=True)
        with self.assertRaises(ConnectionError):
            await self.connect(url, token="temporary-test-token", ssl_context=self.client_context)
        # Rejected upgrades also release their socket rather than leaving it open.
        self.assertEqual(await asyncio.wait_for(completed, 3), b"")

    async def test_control_binary_and_heartbeat_round_trip_over_tls(self):
        control = {"type": "new", "name": "terminal-测试", "cols": 220, "rows": 50, "id": 17}
        payloads = [b"\x00\xfftest", bytes(range(256)), bytes(range(256)) * 1025]
        ping = b"heartbeat-check"

        async def exchange(reader, writer):
            frames = []
            control_frame = await read_client_frame(reader)
            frames.append(control_frame)
            await send_server_frame(writer, 1, control_frame[1])
            for _ in payloads:
                frame = await read_client_frame(reader)
                frames.append(frame)
                # Reverse direction uses a different binary kind to emulate hub input.
                await send_server_frame(writer, 2, bytes([node.KIND_INPUT]) + frame[1][1:])
            await send_server_frame(writer, 9, ping)
            frames.append(await read_client_frame(reader))
            # recv() consumes ping and responds with pong before returning this message.
            await send_server_frame(writer, 1, b'{"type":"complete"}')
            return frames

        url, completed = await self.start_peer(on_ws=exchange)
        ws = await self.connect(url, token="temporary-test-token", ssl_context=self.client_context)
        await ws.send_json(control)
        opcode, response = await asyncio.wait_for(ws.recv(), 3)
        self.assertEqual(opcode, 1)
        self.assertEqual(json.loads(response), control)
        for index, payload in enumerate(payloads, start=1):
            await ws.send_binary(node.KIND_OUTPUT, index, payload)
            opcode, response = await asyncio.wait_for(ws.recv(), 3)
            self.assertEqual(opcode, 2)
            self.assertEqual(response, bytes([node.KIND_INPUT]) + index.to_bytes(8, "big") + payload)
        self.assertEqual(await asyncio.wait_for(ws.recv(), 3), (1, b'{"type":"complete"}'))
        frames = await asyncio.wait_for(completed, 3)
        self.assertTrue(all(masked for _, _, masked in frames))
        self.assertEqual(frames[0][:2], (1, json.dumps(control).encode()))
        for index, (frame, payload) in enumerate(zip(frames[1:-1], payloads), start=1):
            self.assertEqual(frame[:2],
                             (2, bytes([node.KIND_OUTPUT]) + index.to_bytes(8, "big") + payload))
        self.assertEqual(frames[-1][:2], (10, ping))

    async def test_idle_probe_does_not_discard_partial_tls_websocket_frame(self):
        control = {"type": "test-control", "value": "continued after idle probe"}
        payload = json.dumps(control).encode()

        async def exchange(reader, writer):
            hello = await read_client_frame(reader)
            # Deliver the frame header and only part of its JSON body first.
            writer.write(bytes([0x81, len(payload)]) + payload[:5])
            await writer.drain()
            probe = await read_client_frame(reader)
            writer.write(payload[5:])
            await writer.drain()
            return hello, probe

        url, completed = await self.start_peer(on_ws=exchange)
        agent = node.Agent(url, "temporary-test-token", "test", ssl_context=self.client_context)
        agent.ws = await self.connect(url, token=agent.token, ssl_context=self.client_context)
        wait_for = asyncio.wait_for

        async def quick_idle_probe(awaitable, timeout):
            return await wait_for(awaitable, 0.01 if timeout == 60 else timeout)

        with patch.object(node.asyncio, "wait_for", side_effect=quick_idle_probe):
            with patch.object(agent, "handle", new_callable=AsyncMock,
                              side_effect=node.WsClosed) as handle:
                with self.assertRaises(node.WsClosed):
                    await wait_for(agent.serve(), 3)
                handle.assert_awaited_once_with(control)
        hello, probe = await asyncio.wait_for(completed, 3)
        self.assertEqual(json.loads(hello[1])["type"], "hello")
        self.assertEqual(probe, (9, b"", True))

    async def test_session_output_sender_survives_connection_failure(self):
        session = node.Session.__new__(node.Session)
        session.sid = 17
        send = AsyncMock(side_effect=[ConnectionError("temporary disconnect"), None])
        session.agent = SimpleNamespace(send_binary=send)
        session.outq = asyncio.Queue()
        for payload in (b"before reconnect", b"after reconnect", None):
            session.outq.put_nowait(payload)
        await asyncio.wait_for(session._send_loop(), 1)
        self.assertEqual(send.await_count, 2)
        send.assert_has_awaits([
            call(node.KIND_OUTPUT, session.sid, b"before reconnect"),
            call(node.KIND_OUTPUT, session.sid, b"after reconnect"),
        ])
        self.assertTrue(session.outq.empty())

    async def test_successful_hello_resets_reconnect_backoff(self):
        agent = node.Agent("wss://localhost/ws-node", "temporary-test-token", "test")
        connection = SimpleNamespace(close=AsyncMock())
        delays = []
        attempts = 0

        async def serve():
            nonlocal attempts
            attempts += 1
            if attempts == 4:
                await agent.handle({"type": "hello-ok"})
            raise node.WsClosed("simulated disconnect")

        async def record_delay(delay):
            delays.append(delay)
            if len(delays) == 5:
                raise asyncio.CancelledError

        with patch.object(node.Ws, "connect", new_callable=AsyncMock, return_value=connection):
            with patch.object(agent, "serve", side_effect=serve), \
                    patch.object(agent, "maybe_portal_login", new_callable=AsyncMock), \
                    patch.object(node.asyncio, "sleep", side_effect=record_delay), \
                    patch("builtins.print"):
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(agent.run(), 1)
        self.assertEqual(delays, [1, 2, 4, 1, 2])
        self.assertEqual(attempts, 5)
        self.assertEqual(connection.close.await_count, 5)
        self.assertIsNone(agent.ws)

    def test_server_tls_configuration_requires_both_certificate_and_key(self):
        for environment in ({"TMUX_WEB_TLS_CERT": str(self.cert)},
                            {"TMUX_WEB_TLS_KEY": str(self.key)}):
            with self.subTest(environment=list(environment)), patch.dict(os.environ, environment, clear=True):
                with self.assertRaises((ValueError, RuntimeError)):
                    server.tls_context()

    def test_server_tls_configuration_loads_certificate_and_requires_tls12(self):
        with patch.dict(os.environ, {"TMUX_WEB_TLS_CERT": str(self.cert),
                                     "TMUX_WEB_TLS_KEY": str(self.key)}, clear=True):
            context = server.tls_context()
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.protocol, ssl.PROTOCOL_TLS_SERVER)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_server_without_tls_environment_supports_reverse_proxy_termination(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(server.tls_context())


if __name__ == "__main__":
    unittest.main()
