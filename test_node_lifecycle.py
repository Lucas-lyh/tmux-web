"""Isolated filesystem, PTY and connection lifecycle regressions; no live nodes."""

import asyncio
import contextlib
import json
import os
from pathlib import Path
import tempfile
import time
import tty
import unittest
from types import SimpleNamespace
from unittest import mock

import node


class UploadSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tmux-upload-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_root_symlink_cannot_delete_outside_data(self):
        outside = self.base / "outside"
        valuable = outside / "up-valuable"
        valuable.mkdir(parents=True)
        (valuable / "keep.txt").write_text("keep")
        os.utime(valuable, (0, 0))
        root = self.base / "uploads"
        root.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            node.cleanup_upload_root(str(root))
        self.assertEqual((valuable / "keep.txt").read_text(), "keep")

    def test_cleanup_only_removes_owned_old_upload_directories(self):
        root = self.base / "uploads"
        root.mkdir(mode=0o755)
        old = root / "up-old"
        unrelated = root / "old-project"
        fresh = root / "up-fresh"
        for directory in (old, unrelated, fresh):
            directory.mkdir()
            (directory / "data").write_text("test")
        os.utime(old, (0, 0))
        os.utime(unrelated, (0, 0))
        (root / "up-link").symlink_to(unrelated, target_is_directory=True)
        node.cleanup_upload_root(str(root))
        self.assertFalse(old.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue(fresh.exists())
        self.assertTrue((root / "up-link").is_symlink())
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)

    def test_wrong_owner_is_rejected(self):
        root = self.base / "uploads"
        root.mkdir()
        with mock.patch.object(node.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(ValueError):
                node.ensure_private_upload_root(str(root))

    def test_excess_upload_is_rejected_before_writing_and_aborted(self):
        transfer = node.UploadTransfer(str(self.base / "uploads"), "data", 4)
        transfer.write(b"ab")
        with self.assertRaisesRegex(ValueError, "declared size"):
            transfer.write(b"cde")
        self.assertTrue(transfer.file.closed)
        self.assertFalse(Path(transfer.directory).exists())
        self.assertEqual(transfer.received, 2)
        transfer.abort()

    def test_incomplete_upload_is_removed_and_finished_upload_is_retained(self):
        root = str(self.base / "uploads")
        partial = node.UploadTransfer(root, "partial", 2)
        partial.write(b"x")
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            partial.finish()
        self.assertFalse(Path(partial.path).exists())
        complete = node.UploadTransfer(root, "complete", 2)
        complete.write(b"ok")
        path = Path(complete.finish())
        complete.abort()
        self.assertEqual(path.read_bytes(), b"ok")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_creation_failure_does_not_leave_upload_directory(self):
        root = self.base / "uploads"
        real_open = os.open

        def failed_file_open(path, flags, *args, **kwargs):
            if os.path.basename(path) == "fail.txt":
                raise OSError("simulated disk failure")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(node.os, "open", side_effect=failed_file_open):
            with self.assertRaises(OSError):
                node.UploadTransfer(str(root), "fail.txt", 1)
        self.assertEqual(list(root.iterdir()), [])


class PtyLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.master, self.slave = os.openpty()
        tty.setraw(self.slave)
        os.set_blocking(self.slave, False)
        self.writer = None

    async def asyncTearDown(self):
        if self.writer is not None:
            self.writer.close()
        for fd in (self.master, self.slave):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)

    async def read_bytes(self, size):
        output = bytearray()
        deadline = asyncio.get_running_loop().time() + 2
        while len(output) < size:
            try:
                output.extend(os.read(self.slave, size - len(output)))
            except BlockingIOError:
                await asyncio.sleep(0.001)
            if asyncio.get_running_loop().time() > deadline:
                self.fail("PTY writer did not drain")
        return bytes(output)

    async def test_stalled_pty_does_not_block_and_full_queue_does_not_kill_it(self):
        self.writer = node.PtyWriter(self.master, max_buffer=65536)
        payload = bytes(range(256)) * 256
        self.assertTrue(self.writer.write(payload))
        self.assertGreater(self.writer.pending_bytes, 0)
        pending = self.writer.pending_bytes
        self.assertFalse(self.writer.write(payload))
        self.assertEqual(self.writer.pending_bytes, pending)
        await asyncio.wait_for(asyncio.sleep(0), 0.2)
        self.assertEqual(await self.read_bytes(len(payload)), payload)
        self.assertEqual(self.writer.pending_bytes, 0)
        self.assertTrue(self.writer.write(b"still alive"))
        self.assertEqual(await self.read_bytes(11), b"still alive")

    async def test_partial_write_and_eagain_preserve_exact_input(self):
        self.writer = node.PtyWriter(self.master)
        real_write = os.write
        calls = 0

        def partial(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, data[:3])
            if calls == 2:
                raise BlockingIOError()
            return real_write(fd, data)

        with mock.patch.object(node.os, "write", side_effect=partial):
            self.assertTrue(self.writer.write(b"abcdef"))
            self.assertEqual(self.writer.pending_bytes, 3)
            self.assertEqual(await self.read_bytes(6), b"abcdef")
        self.assertEqual(self.writer.pending_bytes, 0)

    async def test_reader_eagain_does_not_finish_session(self):
        session = node.Session.__new__(node.Session)
        session.fd = self.master
        session._finish = mock.AsyncMock()
        with mock.patch.object(node.os, "read", side_effect=BlockingIOError):
            session._on_read()
        await asyncio.sleep(0)
        session._finish.assert_not_awaited()

    async def test_full_output_queue_cannot_leave_sender_alive_after_finish(self):
        session = node.Session.__new__(node.Session)
        session.sid, session.fd, session.dead = 1, -1, False
        session.input_writer = mock.Mock()
        session.agent = SimpleNamespace(sessions={1: session}, send_binary=mock.AsyncMock())
        session.outq = asyncio.Queue(maxsize=512)
        for _ in range(512):
            session.outq.put_nowait(b"old output")
        session._reap = mock.AsyncMock()
        session.sender = asyncio.create_task(session._send_loop())
        # Enter shutdown before scheduling the sender. wait_for would itself
        # schedule a new task and let Python 3.8 drain the queue first.
        await session._finish(False)
        self.assertTrue(session.sender.done())
        self.assertNotIn(1, session.agent.sessions)
        session.agent.send_binary.assert_not_awaited()
        session.input_writer.close.assert_called_once()

    async def test_invalid_dimensions_fail_before_fork(self):
        with mock.patch.object(node.pty, "fork") as fork:
            with self.assertRaises(ValueError):
                node.Session(None, 1, "invalid", -1, 50)
            fork.assert_not_called()

    async def test_failure_after_fork_closes_pty_and_schedules_child_reaping(self):
        fd = self.master
        with mock.patch.object(node.pty, "fork", return_value=(987654321, fd)), \
                mock.patch.object(node, "set_winsize", side_effect=OSError("simulated ioctl failure")), \
                mock.patch.object(node.os, "kill") as kill, \
                mock.patch.object(node.Session, "_reap", new_callable=mock.AsyncMock) as reap:
            with self.assertRaises(OSError):
                node.Session(None, 1, "failed", 220, 50)
            self.master = None
            with self.assertRaises(OSError):
                os.fstat(fd)
            kill.assert_called_once_with(987654321, node.signal.SIGKILL)
            await asyncio.sleep(0)
            reap.assert_awaited_once()


class FakeConnection:
    def __init__(self):
        self.json = []
        self.binary = []
        self.close = mock.AsyncMock()

    async def send_json(self, message):
        self.json.append(dict(message))

    async def send_binary(self, kind, rid, payload):
        self.binary.append((kind, rid, bytes(payload)))


class AgentTransferTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tmux-agent-test-")
        self.base = Path(self.temp.name)
        self.root_patch = mock.patch.object(node, "UPLOAD_DIR", str(self.base / "uploads"))
        self.root_patch.start()
        self.agent = node.Agent("ws://127.0.0.1:59999/ws-node", "isolated-test-key", "isolated")
        self.connection = FakeConnection()
        self.agent.ws = self.connection

    async def asyncTearDown(self):
        await self.agent._reset_transfers()
        self.root_patch.stop()
        self.temp.cleanup()

    async def test_upload_excess_aborts_only_that_transfer(self):
        await self.agent._put_start({"id": 1, "name": "data", "size": 4})
        transfer = self.agent.puts[1]
        await self.agent._put_chunk(1, b"excess")
        self.assertNotIn(1, self.agent.puts)
        self.assertTrue(transfer.file.closed)
        self.assertFalse(Path(transfer.directory).exists())
        self.assertFalse(self.connection.json[-1]["ok"])
        self.connection.close.assert_not_awaited()

    async def test_abort_duplicate_id_and_expiry_close_old_files(self):
        await self.agent._put_start({"id": 1, "name": "first", "size": 4})
        first = self.agent.puts[1]
        await self.agent._put_start({"id": 1, "name": "second", "size": 4})
        second = self.agent.puts[1]
        self.assertTrue(first.file.closed)
        self.assertFalse(Path(first.directory).exists())
        await self.agent.handle({"type": "file-put-abort", "id": 1})
        self.assertTrue(second.file.closed)
        await self.agent._put_start({"id": 2, "name": "expired", "size": 4})
        expired = self.agent.puts[2]
        expired.updated_at -= node.UPLOAD_IDLE_TIMEOUT + 1
        self.agent._last_upload_sweep = 0
        self.agent._expire_uploads()
        self.assertTrue(expired.file.closed)
        self.assertFalse(self.agent.puts)

    async def test_download_never_switches_to_new_connection(self):
        path = self.base / "download"
        path.write_bytes(b"x" * (node.CHUNK + 1))
        first_sent, release = asyncio.Event(), asyncio.Event()
        original_send = self.connection.send_binary

        async def blocked(*args):
            await original_send(*args)
            first_sent.set()
            await release.wait()

        self.connection.send_binary = blocked
        task = asyncio.create_task(self.agent._file_get({"id": 3, "path": str(path)}))
        await first_sent.wait()
        new_connection = FakeConnection()
        self.agent.ws = new_connection
        release.set()
        await task
        self.assertEqual(len(self.connection.binary), 1)
        self.assertEqual(new_connection.binary, [])
        self.assertEqual(new_connection.json, [])

    async def test_download_cancel_finishes_current_chunk_without_closing_link(self):
        path = self.base / "download"
        path.write_bytes(b"x" * (node.CHUNK + 1))
        first_sent, release = asyncio.Event(), asyncio.Event()
        original_send = self.connection.send_binary

        async def blocked(*args):
            await original_send(*args)
            first_sent.set()
            await release.wait()

        self.connection.send_binary = blocked
        await self.agent.handle({"type": "file-get", "id": 4, "path": str(path)})
        task = self.agent._file_tasks[4]
        await first_sent.wait()
        await self.agent.handle({"type": "file-get-cancel", "id": 4})
        release.set()
        await task
        self.assertEqual(len(self.connection.binary), 1)
        self.assertEqual([m["type"] for m in self.connection.json], ["file-meta"])
        self.connection.close.assert_not_awaited()

    async def test_disconnect_cancels_downloads_aborts_uploads_and_keeps_shell(self):
        await self.agent._put_start({"id": 1, "name": "partial", "size": 4})
        partial = self.agent.puts[1]
        shell = SimpleNamespace(watchers=2, dead=False, kill=mock.AsyncMock())
        self.agent.sessions[7] = shell
        connection = SimpleNamespace(close=mock.AsyncMock())
        with mock.patch.object(node.Ws, "connect", new_callable=mock.AsyncMock, return_value=connection), \
                mock.patch.object(node.NoiseChannel, "establish", new_callable=mock.AsyncMock, return_value=connection), \
                mock.patch.object(self.agent, "serve", side_effect=node.WsClosed), \
                mock.patch.object(self.agent, "maybe_portal_login", new_callable=mock.AsyncMock), \
                mock.patch.object(node.asyncio, "sleep", side_effect=asyncio.CancelledError), \
                mock.patch("builtins.print"):
            with self.assertRaises(asyncio.CancelledError):
                await self.agent.run()
        self.assertTrue(partial.file.closed)
        self.assertFalse(Path(partial.directory).exists())
        self.assertFalse(self.agent.puts)
        self.assertIs(self.agent.sessions[7], shell)
        self.assertFalse(shell.dead)
        self.assertEqual(shell.watchers, 0)
        shell.kill.assert_not_awaited()

    async def test_reset_cancels_tracked_download(self):
        path = self.base / "download"
        path.write_bytes(b"data")
        waiting = asyncio.Event()

        async def blocked(*args):
            waiting.set()
            await asyncio.Event().wait()

        self.connection.send_binary = blocked
        await self.agent.handle({"type": "file-get", "id": 5, "path": str(path)})
        task = self.agent._file_tasks[5]
        await waiting.wait()
        await self.agent._reset_transfers()
        self.assertTrue(task.done())
        self.assertFalse(self.agent._file_tasks)
        self.assertFalse(self.agent._download_cancels)

    async def test_file_stat_sends_metadata_without_opening_or_streaming_file(self):
        path = self.base / "stat-only"
        path.write_bytes(b"metadata")
        with mock.patch("builtins.open", side_effect=AssertionError("file-stat must not open payload")):
            await self.agent.handle({"type": "file-stat", "id": 6, "path": str(path)})
        self.assertEqual(self.connection.json, [{"type": "file-meta", "id": 6, "ok": True,
                                                "size": 8, "name": "stat-only"}])
        self.assertEqual(self.connection.binary, [])

    async def test_input_overflow_reports_error_and_continues_other_commands(self):
        shell = SimpleNamespace(sid=7, name="shell", cols=220, rows=50, dead=False,
                                input_writer=mock.Mock(write=mock.Mock(return_value=False)),
                                resize=mock.Mock(), kill=mock.AsyncMock())
        self.agent.sessions[7] = shell
        payload = bytes([node.KIND_INPUT]) + (7).to_bytes(8, "big") + b"input"
        resize = json.dumps({"type": "resize", "sid": 7, "cols": 80, "rows": 24}).encode()
        self.connection.recv = mock.AsyncMock(side_effect=[(2, payload), (1, resize), node.WsClosed()])
        with self.assertRaises(node.WsClosed):
            await self.agent.serve()
        self.assertEqual(self.connection.json[1]["type"], "input-error")
        self.assertEqual(self.connection.json[1]["sid"], 7)
        shell.resize.assert_called_once_with(80, 24)
        shell.kill.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
