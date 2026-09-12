import contextlib
import http.client
import io
import os
from pathlib import Path
import select
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import client


class _Socket:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, *args):
        return io.BytesIO(self.wire)


def response(body, length=None):
    header = b"HTTP/1.1 200 OK\r\n"
    if length is not None:
        header += b"Content-Length: " + str(length).encode() + b"\r\n"
    result = http.client.HTTPResponse(_Socket(header + b"\r\n" + body))
    result.begin()
    return result


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.destination = self.root / "result.bin"
        self.destination.write_bytes(b"original")

    def download(self, data, length):
        with patch.object(client, "secret", return_value="synthetic-fixture"), \
             patch.object(client.urllib.request, "urlopen", return_value=response(data, length)):
            client.api_download(None, "/fixture/result.bin", str(self.destination))

    def test_truncated_content_length_keeps_original_and_cleans_temp(self):
        with self.assertRaisesRegex(IOError, "incomplete download"):
            self.download(b"short", 100)
        self.assertEqual(self.destination.read_bytes(), b"original")
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_success_replaces_only_after_download_in_same_directory(self):
        original_replace = os.replace
        def replace(source, destination):
            self.assertEqual(Path(source).parent, self.root)
            self.assertEqual(self.destination.read_bytes(), b"original")
            self.assertEqual(Path(source).read_bytes(), b"complete")
            original_replace(source, destination)
        with patch.object(client.os, "replace", side_effect=replace):
            self.download(b"complete", 8)
        self.assertEqual(self.destination.read_bytes(), b"complete")
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_empty_and_unknown_length_responses(self):
        self.download(b"", 0)
        self.assertEqual(self.destination.read_bytes(), b"")
        self.download(b"stream", None)
        self.assertEqual(self.destination.read_bytes(), b"stream")

    def test_invalid_length_and_replace_failure_preserve_original(self):
        with self.assertRaises(ValueError):
            self.download(b"", -1)
        with patch.object(client.os, "replace", side_effect=OSError("fixture replace failure")):
            with self.assertRaises(OSError):
                self.download(b"new", 3)
        self.assertEqual(self.destination.read_bytes(), b"original")
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_midstream_failure_removes_partial_file(self):
        class Broken:
            headers = {"Content-Length": "100"}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, amount): raise ConnectionError("fixture connection dropped")
        with patch.object(client, "secret", return_value="synthetic-fixture"), \
             patch.object(client.urllib.request, "urlopen", return_value=Broken()):
            with self.assertRaises(ConnectionError):
                client.api_download(None, "/fixture/file", str(self.destination))
        self.assertEqual(self.destination.read_bytes(), b"original")
        self.assertEqual(list(self.root.iterdir()), [self.destination])


class ShellCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = dict(os.environ)
        for key in ("BASH_ENV", "ENV", "TMUX", "TMUX_PANE"):
            env.pop(key, None)
        env.update(HOME=self.tmp.name, PS1="", PS2="")
        self.shell = subprocess.Popen(
            ["/bin/bash", "--noprofile", "--norc"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.tmp.name, env=env,
        )
        self.output = b""
        os.set_blocking(self.shell.stdout.fileno(), False)
        self.addCleanup(self.close_shell)
        self.send_patch = patch.object(client, "send", side_effect=self.send)
        self.capture_patch = patch.object(client, "capture", side_effect=self.capture)
        self.send_patch.start()
        self.capture_patch.start()
        self.addCleanup(self.send_patch.stop)
        self.addCleanup(self.capture_patch.stop)

    def close_shell(self):
        with contextlib.suppress(BrokenPipeError):
            self.shell.stdin.close()
        try:
            self.shell.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.shell.kill()
            self.shell.wait(timeout=2)
        self.shell.stdout.close()

    def send(self, session, text, **kwargs):
        self.shell.stdin.write(text.encode())
        self.shell.stdin.flush()

    def capture(self, session, lines=300, **kwargs):
        if select.select([self.shell.stdout], [], [], .02)[0]:
            while True:
                try:
                    chunk = os.read(self.shell.stdout.fileno(), 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                self.output += chunk
        return self.output.decode().splitlines(keepends=True)[-lines:] and "".join(
            self.output.decode().splitlines(keepends=True)[-lines:]
        ) or ""

    def run_command(self, command):
        return client.run_result("fixture", command, timeout=2, poll=.01)

    def test_printf_comment_trailing_semicolon_and_exit_code(self):
        for command, output, status in (
            ("printf hello", "hello", 0),
            ("true # trailing comment", "", 0),
            ("printf hello;", "hello", 0),
            ("false", "", 1),
            ("printf failure >&2; (exit 7)", "failure", 7),
            ("printf 'a\\n\\nb\\n'", "a\n\nb", 0),
            ("printf '\\\\n'", "\\n", 0),
        ):
            with self.subTest(command=command):
                result = self.run_command(command)
                self.assertEqual((result.output, result.returncode, result.truncated), (output, status, False))

    def test_current_shell_environment_and_directory_are_preserved(self):
        directory = Path(self.tmp.name) / "next"
        directory.mkdir()
        self.run_command("export AB_FIXTURE_VALUE=preserved; cd " + str(directory))
        result = self.run_command('printf "%s:%s" "$AB_FIXTURE_VALUE" "$PWD"')
        self.assertEqual(result.output, "preserved:" + str(directory))
        self.assertEqual(client.run("fixture", "printf compatibility", timeout=2, poll=.01), "compatibility")

    def test_large_output_reports_truncation(self):
        result = self.run_command("for ((i=0;i<350;i++)); do printf 'line\\n'; done")
        self.assertTrue(result.truncated)
        self.assertEqual(result.returncode, 0)
        self.assertLessEqual(len(result.output.splitlines()), 300)

    def test_history_is_excluded(self):
        self.run_command("printf first")
        self.assertEqual(self.run_command("printf second").output, "second")

    def test_cli_returns_command_exit_code(self):
        with patch.object(client.sys, "argv", ["client.py", "run", "fixture", "false"]), \
             patch("builtins.print"):
            self.assertEqual(client.main(), 1)


class DeadlineTests(unittest.TestCase):
    def test_monotonic_timeout_and_validation(self):
        with patch.object(client, "send"), patch.object(client, "capture", return_value=""), \
             patch.object(client.time, "time", side_effect=AssertionError("wall clock used")):
            with self.assertRaises(TimeoutError):
                client.run_result("fixture", "sleep 100", timeout=.03, poll=.01)
        with patch.object(client, "send") as send:
            with self.assertRaises(ValueError):
                client.run_result("fixture", "true", timeout=0)
            send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
