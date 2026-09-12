"""Bounded local scheduling and file-worker cancellation regressions."""

import asyncio
import contextlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import node


class MemoryConnection:
    def __init__(self):
        self.messages = []

    async def send_json(self, message):
        self.messages.append(dict(message))

    async def send_binary(self, kind, rid, payload):
        self.messages.append((kind, rid, bytes(payload)))


class BlockingStream:
    def __init__(self, path):
        self.stream = open(path, "rb")
        self.started = threading.Event()
        self.release = threading.Event()
        self.reading = False
        self.closed_during_read = False

    def read(self, size):
        self.reading = True
        self.started.set()
        try:
            if not self.release.wait(3):
                raise TimeoutError("isolated file worker was not released")
            return self.stream.read(size)
        finally:
            self.reading = False

    def close(self):
        self.closed_during_read |= self.reading
        self.stream.close()


class NodeFileLatencyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tmux-latency-test-")
        self.base = Path(self.temp.name)
        self.path = self.base / "payload"
        self.path.write_bytes(b"data")
        self.agent = node.Agent("ws://localhost:59999/ws-node", "isolated-manual-key", "test")
        self.connection = MemoryConnection()
        self.agent.ws = self.connection
        self.upload_patch = mock.patch.object(node, "UPLOAD_DIR", str(self.base / "uploads"))
        self.upload_patch.start()

    async def asyncTearDown(self):
        await self.agent._reset_transfers()
        self.upload_patch.stop()
        self.temp.cleanup()

    async def wait_thread(self, event):
        deadline = asyncio.get_running_loop().time() + 2
        while not event.is_set():
            self.assertLess(asyncio.get_running_loop().time(), deadline, "file worker did not start")
            await asyncio.sleep(0.001)

    async def test_slow_download_read_keeps_control_messages_responsive(self):
        stream = BlockingStream(self.path)
        with mock.patch.object(self.agent, "_open_download", return_value=(stream, str(self.path), SimpleNamespace(st_size=4))):
            task = asyncio.create_task(self.agent._file_get({"id": 1, "path": str(self.path)}))
            try:
                await self.wait_thread(stream.started)
                self.agent.sessions[7] = SimpleNamespace(buf=bytearray(b"terminal ready\n"))
                await asyncio.wait_for(self.agent.handle({"type": "capture", "sid": 7, "id": 2}), 0.2)
                self.assertEqual(self.connection.messages[-1]["type"], "reply")
                self.assertIn("terminal ready", self.connection.messages[-1]["text"])
                self.assertFalse(task.done())
            finally:
                stream.release.set()
                await task
        self.assertTrue(stream.stream.closed)
        self.assertFalse(stream.closed_during_read)

    async def test_cancelled_download_waits_for_worker_before_closing_descriptor(self):
        stream = BlockingStream(self.path)
        with mock.patch.object(self.agent, "_open_download", return_value=(stream, str(self.path), SimpleNamespace(st_size=4))):
            task = asyncio.create_task(self.agent._file_get({"id": 1, "path": str(self.path)}))
            try:
                await self.wait_thread(stream.started)
                task.cancel()
                await asyncio.sleep(0.005)
                task.cancel()  # Repeated cancellation must not cancel the worker future.
                await asyncio.sleep(0.005)
                self.assertFalse(task.done())
                self.assertFalse(stream.stream.closed)
            finally:
                stream.release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertTrue(stream.stream.closed)
        self.assertFalse(stream.closed_during_read)

    async def test_cancelled_open_disposes_the_file_not_returned_to_caller(self):
        started, release = threading.Event(), threading.Event()
        created = []

        def delayed_open(message):
            stream = open(self.path, "rb")
            created.append(stream)
            started.set()
            release.wait(3)
            return stream, str(self.path), SimpleNamespace(st_size=4)

        with mock.patch.object(self.agent, "_open_download", side_effect=delayed_open):
            task = asyncio.create_task(self.agent._file_get({"id": 1, "path": str(self.path)}))
            try:
                await self.wait_thread(started)
                task.cancel()
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertTrue(created[0].closed)

    async def test_cancelled_upload_creation_aborts_unclaimed_transfer(self):
        started, release = threading.Event(), threading.Event()
        created = []
        constructor = node.UploadTransfer

        def delayed_create(*args):
            transfer = constructor(*args)
            created.append(transfer)
            started.set()
            release.wait(3)
            return transfer

        with mock.patch.object(node, "UploadTransfer", side_effect=delayed_create):
            task = asyncio.create_task(self.agent._put_start({"id": 1, "name": "partial", "size": 4}))
            try:
                await self.wait_thread(started)
                task.cancel()
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertEqual(self.agent.puts, {})
        self.assertTrue(created[0].file.closed)
        self.assertFalse(Path(created[0].directory).exists())

    async def test_cancelled_upload_write_finishes_before_abort_closes_file(self):
        await self.agent._put_start({"id": 1, "name": "partial", "size": 4})
        transfer = self.agent.puts[1]
        original_write = transfer.write
        started, release = threading.Event(), threading.Event()
        closed_during_write = []

        def delayed_write(data):
            started.set()
            release.wait(3)
            closed_during_write.append(transfer.file.closed)
            original_write(data)

        with mock.patch.object(transfer, "write", side_effect=delayed_write):
            task = asyncio.create_task(self.agent._put_chunk(1, b"data"))
            try:
                await self.wait_thread(started)
                task.cancel()
                await asyncio.wait_for(asyncio.sleep(0.005), 0.2)
                self.assertFalse(task.done())
                self.assertFalse(transfer.file.closed)
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        await self.agent._reset_transfers()
        self.assertEqual(closed_during_write, [False])
        self.assertTrue(transfer.file.closed)
        self.assertFalse(Path(transfer.directory).exists())

    async def measure_control_delay(self, chunk_size):
        initiator = node._Noise(bytes(range(32)), True)
        responder = node._Noise(bytes(range(32)), False)
        responder.read_message(initiator.write_message())
        initiator.read_message(responder.write_message())

        class Wire:
            def __init__(self):
                self.frames = []
                self.first_file_record = asyncio.Event()

            async def send(self, ciphertext):
                self.frames.append(ciphertext)
                if len(self.frames) == 2:  # metadata, then first file record
                    self.first_file_record.set()

            async def close(self, code=1000, reason=""):
                pass

        wire = Wire()
        channel = node.NoiseChannel(wire, initiator)
        connection = node.NodeConnection(SimpleNamespace(), channel)
        self.agent.ws = connection
        with mock.patch.object(node, "CHUNK", chunk_size):
            task = asyncio.create_task(self.agent._file_get({"id": 1, "path": str(self.path)}))
            await wire.first_file_record.wait()
            start = time.perf_counter()
            await connection.send_json({"type": "reply", "id": 2, "text": "ready"})
            elapsed = time.perf_counter() - start
            await task

        before_reply = 0
        body = bytearray()
        for record in wire.frames:
            clear = responder.decrypt(record)
            kind, total, offset = node.NOISE_HEADER.unpack_from(clear)
            self.assertEqual(offset, len(body))
            body.extend(clear[node.NOISE_HEADER.size:])
            if len(body) == total:
                if kind == 1 and json.loads(body)["type"] == "reply":
                    break
                if kind == 2:
                    self.assertEqual(body[0], node.KIND_FILE_DATA)
                    before_reply += len(body) - 9
                body.clear()
            await asyncio.sleep(0)
        return elapsed, before_reply

    async def test_small_chunks_release_noise_send_lock_for_control_messages(self):
        self.assertLessEqual(node.CHUNK, 32 * 1024)
        self.path.write_bytes(b"x" * (256 * 1024 + 1))
        previous_delay, previous_bytes = await self.measure_control_delay(256 * 1024)
        current_delay, current_bytes = await self.measure_control_delay(node.CHUNK)
        self.assertEqual(previous_bytes, 256 * 1024)
        self.assertEqual(current_bytes, node.CHUNK)
        self.assertLess(current_delay, previous_delay * 0.5)
        print("Local Noise control-queue comparison: 256KiB={:.2f}ms, 16KiB={:.2f}ms".format(
            previous_delay * 1000, current_delay * 1000))


if __name__ == "__main__":
    unittest.main()
