import json
import os
import secrets
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import server


class AuthTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.auth_file = Path(tmp.name) / '.auth.json'
        for target, value in (('AUTH_FILE', str(self.auth_file)), ('_AUTH', None)):
            patcher = patch.object(server, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        env = patch.dict(os.environ, {'TMUX_WEB_PASSWORD': ''})
        env.start()
        self.addCleanup(env.stop)
        tty = patch.object(server.sys.stdin, 'isatty', return_value=False)
        tty.start()
        self.addCleanup(tty.stop)

    def test_first_start_requires_explicit_password(self):
        with self.assertRaisesRegex(RuntimeError, 'TMUX_WEB_PASSWORD'):
            server._load_auth()
        self.assertFalse(self.auth_file.exists())

    def test_initialize_and_keep_existing_password(self):
        password = secrets.token_urlsafe(24)
        with patch.dict(os.environ, {'TMUX_WEB_PASSWORD': password}):
            self.assertTrue(server.check_password(password))
        self.assertEqual(self.auth_file.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(password, self.auth_file.read_text())
        existing = self.auth_file.read_bytes()
        with patch.dict(os.environ, {'TMUX_WEB_PASSWORD': secrets.token_urlsafe(24)}):
            server._AUTH = None
            self.assertTrue(server.check_password(password))
            self.assertEqual(self.auth_file.read_bytes(), existing)
        self.assertFalse(server.check_password(secrets.token_urlsafe(24)))

    def test_password_change_persists(self):
        original, replacement = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        with patch.dict(os.environ, {'TMUX_WEB_PASSWORD': original}):
            server.check_password(original)
        server.set_password(replacement)
        server._AUTH = None
        self.assertTrue(server.check_password(replacement))
        self.assertFalse(server.check_password(original))

    def test_corrupt_auth_is_not_silently_overwritten(self):
        self.auth_file.write_text('{invalid')
        with self.assertRaises(json.JSONDecodeError):
            server._load_auth()
        self.assertEqual(self.auth_file.read_text(), '{invalid')

    def test_interactive_setup_requires_confirmation(self):
        password = secrets.token_urlsafe(24)
        with patch.object(server.sys.stdin, 'isatty', return_value=True):
            with patch.object(server.getpass, 'getpass', side_effect=[password, '']):
                with self.assertRaisesRegex(RuntimeError, 'do not match'):
                    server._load_auth()
            self.assertFalse(self.auth_file.exists())
            with patch.object(server.getpass, 'getpass', side_effect=[password, password]):
                self.assertTrue(server.check_password(password))


class SessionTests(unittest.TestCase):
    def test_remote_sessions_visible_without_local_tmux_sessions(self):
        node = SimpleNamespace(sessions={1: {'name': 'train'}}, watchers={})
        with patch.object(server, 'tmux', return_value=subprocess.CompletedProcess([], 1, '', '')):
            with patch.object(server, 'NODES', {'gpu1': node}):
                sessions = server.list_sessions()
        self.assertEqual([s['name'] for s in sessions], ['gpu1:train'])


class NodeAuthenticationTests(unittest.TestCase):
    def test_bearer_and_legacy_query_authentication(self):
        secret = secrets.token_urlsafe(24)
        with patch.object(server, 'node_secret', return_value=secret):
            request = SimpleNamespace(headers={'Authorization': 'Bearer ' + secret})
            self.assertTrue(server.node_authed(request, {}))
            self.assertTrue(server.node_authed(SimpleNamespace(headers={}), {'token': [secret]}))
            self.assertFalse(server.node_authed(SimpleNamespace(headers={}), {}))
            for invalid in ('Bearer wrong', 'Bearer 非法', 'Basic invalid'):
                request = SimpleNamespace(headers={'Authorization': invalid})
                self.assertFalse(server.node_authed(request, {'token': [secret]}))


if __name__ == '__main__':
    unittest.main()
