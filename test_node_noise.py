"""Noise interoperability and tamper tests using in-memory, observable transports."""

import asyncio
import hashlib
import hmac
import json
import secrets
import struct
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch


import node


# These are the public wire format, deliberately independent of node's helpers.
PROTOCOL = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
PROLOGUE = b"tmux-web/node/v2"
PSK_DOMAIN = b"tmux-web/node/v2/psk"
MAX_MESSAGE = 8 * 1024 * 1024
MAX_CHUNK = 65510
EOF = object()


class MemoryRaw:
    """Unencrypted peer transport: capture every byte visible on the wire."""

    def __init__(self):
        self.inbox = asyncio.Queue()
        self.sent = []
        self.closed = False
        self.close_code = None
        self.peer = None

    async def send(self, data):
        if self.closed:
            raise node.WsClosed("memory transport closed")
        self.sent.append(data)
        self.peer.inbox.put_nowait(data)
        # Force competing senders to interleave unless the channel serializes them.
        await asyncio.sleep(0)

    async def recv(self):
        data = await self.inbox.get()
        if data is EOF:
            raise node.WsClosed("memory transport closed")
        return data

    async def close(self, code=1000, reason=""):
        if self.closed:
            return
        self.closed = True
        self.close_code = code
        self.inbox.put_nowait(EOF)
        self.peer.inbox.put_nowait(EOF)


def standard_noise(token, *, initiator):
    """Primitive peer for testing record framing; fixed vectors test the cipher independently."""
    return node._Noise(hmac.digest(token.encode(), PSK_DOMAIN, "sha256"), initiator)


class NodeNoiseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.raws = []
        self.token = secrets.token_urlsafe(32)
        self.addAsyncCleanup(self.close_transports)

    async def close_transports(self):
        for raw in self.raws:
            await raw.close()

    def raw_pair(self):
        left, right = MemoryRaw(), MemoryRaw()
        left.peer, right.peer = right, left
        self.raws.extend((left, right))
        return left, right

    async def channels(self, *, token=None):
        left, right = self.raw_pair()
        token = token or self.token
        client, server = await asyncio.wait_for(asyncio.gather(
            node.NoiseChannel.establish(left, token, initiator=True),
            node.NoiseChannel.establish(right, token, initiator=False),
        ), 3)
        return client, server, left, right

    async def independent_peer(self, *, channel_is_initiator=True):
        channel_raw, independent_raw = self.raw_pair()
        independent = standard_noise(self.token, initiator=not channel_is_initiator)

        async def handshake():
            if channel_is_initiator:
                self.assertEqual(independent.read_message(await independent_raw.recv()), b"")
                await independent_raw.send(bytes(independent.write_message()))
            else:
                await independent_raw.send(bytes(independent.write_message()))
                self.assertEqual(independent.read_message(await independent_raw.recv()), b"")
            self.assertTrue(independent.handshake_finished)

        channel, _ = await asyncio.wait_for(asyncio.gather(
            node.NoiseChannel.establish(channel_raw, self.token, initiator=channel_is_initiator),
            handshake(),
        ), 3)
        return channel, independent, channel_raw, independent_raw

    async def independent_receive(self, raw, noise):
        payload = bytearray()
        expected = None
        while True:
            wire = await raw.recv()
            self.assertIsInstance(wire, bytes)
            self.assertLessEqual(len(wire), 65535)
            plain = noise.decrypt(wire)
            kind, total, offset = struct.unpack("!BII", plain[:9])
            if expected is None:
                expected = kind, total
            self.assertEqual((kind, total), expected)
            self.assertEqual(offset, len(payload))
            payload.extend(plain[9:])
            self.assertLessEqual(len(payload), total)
            if len(payload) == total:
                return payload.decode("utf-8") if kind == 1 else bytes(payload)

    async def independent_send(self, raw, noise, message):
        kind, payload = (1, message.encode("utf-8")) if isinstance(message, str) else (2, message)
        for offset in range(0, max(len(payload), 1), MAX_CHUNK):
            record = struct.pack("!BII", kind, len(payload), offset) + payload[offset:offset + MAX_CHUNK]
            await raw.send(noise.encrypt(record))

    async def test_same_key_handshake_and_bidirectional_messages_hide_metadata(self):
        client, server, client_raw, server_raw = await self.channels()
        name = "private-campus-node-测试"
        hello = json.dumps({"type": "hello", "version": 2, "name": name,
                            "sessions": [{"name": "private-training-session", "sid": 1729}]},
                           ensure_ascii=False)
        output = b"private-terminal-output: uptime and commands"
        await client.send(hello)
        self.assertEqual(await server.recv(), hello)
        await server.send(output)
        self.assertEqual(await client.recv(), output)
        wire = b"".join(client_raw.sent + server_raw.sent)
        for value in (self.token.encode(), name.encode(), hello.encode(), output,
                      b"private-training-session", b'"sessions"'):
            self.assertNotIn(value, wire)
        self.assertTrue(all(isinstance(frame, bytes) for frame in client_raw.sent + server_raw.sent))

    async def test_record_framing_in_both_roles(self):
        for initiator in (True, False):
            with self.subTest(channel_is_initiator=initiator):
                channel, independent, _, peer = await self.independent_peer(channel_is_initiator=initiator)
                for message in ("control-message-中文", bytes(range(256)) * 700, "", b""):
                    await channel.send(message)
                    self.assertEqual(await self.independent_receive(peer, independent), message)
                    await self.independent_send(peer, independent, message)
                    self.assertEqual(await channel.recv(), message)

    async def test_wrong_shared_key_rejects_handshake_and_closes(self):
        left, right = self.raw_pair()
        results = await asyncio.wait_for(asyncio.gather(
            node.NoiseChannel.establish(left, self.token, initiator=True),
            node.NoiseChannel.establish(right, secrets.token_urlsafe(32), initiator=False),
            return_exceptions=True,
        ), 3)
        self.assertTrue(all(isinstance(result, node.NoiseError) for result in results), results)
        self.assertTrue(left.closed)
        self.assertTrue(right.closed)
        self.assertNotIn(self.token.encode(), b"".join(left.sent + right.sent))

    async def test_nonempty_handshake_payload_is_rejected(self):
        raw, peer = self.raw_pair()
        independent = standard_noise(self.token, initiator=True)
        await peer.send(bytes(independent.write_message(b"unexpected handshake metadata")))
        with self.assertRaises(node.NoiseError):
            await node.NoiseChannel.establish(raw, self.token, initiator=False)
        self.assertTrue(raw.closed)

    async def test_modified_ciphertext_is_rejected_and_connection_closes(self):
        client, server, _, server_raw = await self.channels()
        await client.send(b"authenticated payload")
        wire = await server_raw.inbox.get()
        server_raw.inbox.put_nowait(wire[:-1] + bytes([wire[-1] ^ 1]))
        with self.assertRaises(node.NoiseError):
            await server.recv()
        self.assertTrue(server_raw.closed)

    async def test_replayed_ciphertext_is_rejected_and_connection_closes(self):
        client, server, client_raw, server_raw = await self.channels()
        await client.send("first and only accepted message")
        replay = client_raw.sent[-1]
        self.assertEqual(await server.recv(), "first and only accepted message")
        server_raw.inbox.put_nowait(replay)
        with self.assertRaises(node.NoiseError):
            await server.recv()
        self.assertTrue(server_raw.closed)

    async def test_new_connections_use_fresh_keys_for_identical_messages(self):
        wire_messages = []
        handshakes = []
        for _ in range(2):
            client, server, raw, _ = await self.channels()
            handshakes.append(raw.sent[0])
            await client.send(b"same plaintext and shared key on both connections")
            self.assertEqual(await server.recv(), b"same plaintext and shared key on both connections")
            wire_messages.append(raw.sent[-1])
        self.assertNotEqual(handshakes[0], handshakes[1])
        self.assertNotEqual(wire_messages[0], wire_messages[1])

    async def test_eight_mib_message_succeeds_and_larger_send_is_rejected(self):
        client, server, raw, _ = await self.channels()
        payload = b"x" * MAX_MESSAGE
        await client.send(payload)
        self.assertEqual(await server.recv(), payload)
        self.assertGreater(len(raw.sent), 2)
        self.assertTrue(all(len(record) <= 65535 for record in raw.sent))
        previous_frames = len(raw.sent)
        with self.assertRaises((ValueError, node.NoiseError)):
            await client.send(payload + b"x")
        self.assertEqual(len(raw.sent), previous_frames)

    async def test_receive_rejects_claimed_length_above_eight_mib(self):
        channel, independent, raw, peer = await self.independent_peer()
        record = struct.pack("!BII", 2, MAX_MESSAGE + 1, 0) + b"small data"
        await peer.send(independent.encrypt(record))
        with self.assertRaises(node.NoiseError):
            await channel.recv()
        self.assertTrue(raw.closed)

    async def test_concurrent_fragmented_messages_remain_complete_in_both_directions(self):
        client, server, _, _ = await self.channels()
        left_messages = [bytes([index]) * (MAX_CHUNK * 3 + index) for index in range(1, 5)]
        right_messages = [("message-测试-" + str(index)) * 20000 for index in range(4)]

        async def receive_all(channel, count):
            return [await channel.recv() for _ in range(count)]

        *_, left_received, right_received = await asyncio.wait_for(asyncio.gather(
            *(client.send(message) for message in left_messages),
            *(server.send(message) for message in right_messages),
            receive_all(server, len(left_messages)), receive_all(client, len(right_messages)),
        ), 60)
        self.assertCountEqual(left_received, left_messages)
        self.assertCountEqual(right_received, right_messages)

    async def test_plaintext_records_never_fall_back_to_legacy_protocol(self):
        channel, _, raw, peer = await self.independent_peer()
        await peer.send('{"type":"hello","name":"plaintext-injection"}')
        with self.assertRaises(node.NoiseError):
            await channel.recv()
        self.assertTrue(raw.closed)

    async def test_invalid_fragment_offset_is_rejected_after_authentication(self):
        channel, independent, raw, peer = await self.independent_peer()
        await peer.send(independent.encrypt(struct.pack("!BII", 2, 5, 1) + b"bytes"))
        with self.assertRaises(node.NoiseError):
            await channel.recv()
        self.assertTrue(raw.closed)

    async def test_agent_does_not_serve_or_send_plaintext_when_noise_handshake_fails(self):
        agent = node.Agent("ws://localhost:59999/ws-node", self.token, "private-node")
        raw = AsyncMock()
        with patch.object(node.Ws, "connect", new_callable=AsyncMock, return_value=raw), \
                patch.object(node.NoiseChannel, "establish", new_callable=AsyncMock,
                             side_effect=node.NoiseError("simulated wrong key")) as establish, \
                patch.object(agent, "serve", new_callable=AsyncMock) as serve, \
                patch.object(agent, "maybe_portal_login", new_callable=AsyncMock), \
                patch.object(node.asyncio, "sleep", new_callable=AsyncMock,
                             side_effect=asyncio.CancelledError), patch("builtins.print"):
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(agent.run(), 1)
        establish.assert_awaited_once()
        serve.assert_not_awaited()
        raw.send_json.assert_not_awaited()
        raw.send_binary.assert_not_awaited()

    async def test_agent_hello_and_terminal_output_are_only_visible_after_decryption(self):
        channel, independent, wire, peer = await self.independent_peer()
        agent = node.Agent("ws://localhost:59999/ws-node", self.token, "private-campus-node")
        agent.sessions[7] = SimpleNamespace(sid=7, name="private-session", cols=220, rows=50)
        agent.ws = node.NodeConnection(SimpleNamespace(last_seen=time.time()), channel)
        task = asyncio.create_task(agent.serve())
        try:
            hello = json.loads(await asyncio.wait_for(self.independent_receive(peer, independent), 1))
            self.assertEqual(hello, {"type": "hello", "version": 2, "name": agent.name,
                                     "capabilities": ["file-stat", "file-get-cancel", "file-put-abort", "input-error"],
                                     "sessions": [{"sid": 7, "name": "private-session", "cols": 220, "rows": 50}]})
            await agent.send_binary(node.KIND_OUTPUT, 7, b"private terminal output")
            output = await asyncio.wait_for(self.independent_receive(peer, independent), 1)
            self.assertEqual(output, bytes([node.KIND_OUTPUT]) + (7).to_bytes(8, "big")
                             + b"private terminal output")
            captured = b"".join(wire.sent)
            for value in (self.token.encode(), agent.name.encode(), b"private-session",
                          b"private terminal output", b'"sessions"'):
                self.assertNotIn(value, captured)
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task


if __name__ == "__main__":
    unittest.main()
