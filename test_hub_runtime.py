import asyncio
import json
import os
from pathlib import Path
import tempfile
import time
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from hub.runtime import RuntimeConfig
from hub.storage import atomic_json
from hub.targets import split_target
from hub.queues import offer_output
import http_frontend
import server


class RuntimeTests(unittest.TestCase):
    def test_preview_launcher_rejects_live_port_and_source_state(self):
        source=Path(__file__).parent
        for arguments in (['--port','59999'], ['--state-dir',str(source/'should-not-exist')]):
            result=subprocess.run([sys.executable,str(source/'scripts/run_candidate.py'),*arguments],
                                  capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
        self.assertFalse((source/'should-not-exist').exists())

    def test_isolated_paths_socket_and_cookie_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {'TMUX_WEB_STATE_DIR': tmp,
                                         'TMUX_WEB_TMUX_SOCKET': tmp+'/tmux.sock',
                                         'TMUX_WEB_PORT': '60001',
                                         'TMUX_WEB_COOKIE_NAME': 'tmux_web_b_token',
                                         'TMUX_WEB_BLOCKED_PORTS': '59999',
                                         'TMUX': '/production/socket,1,0',
                                         'TMUX_PANE': '%123'}, clear=True):
                runtime=RuntimeConfig.from_environment(Path(__file__).parent)
                self.assertEqual(runtime.state_dir, Path(tmp))
                self.assertEqual(runtime.upload_dir, tmp+'/uploads')
                self.assertEqual(runtime.tmux_argv('list-sessions'), ['tmux','-S',tmp+'/tmux.sock','list-sessions'])
                self.assertNotIn('TMUX',runtime.tmux_environment())
                self.assertNotIn('TMUX_PANE',runtime.tmux_environment())
                self.assertEqual(runtime.cookie_name,'tmux_web_b_token')
                self.assertIn(59999,runtime.blocked_ports)

    def test_relative_socket_and_invalid_cookie_are_rejected(self):
        for values in ({'TMUX_WEB_TMUX_SOCKET':'relative.sock'},
                       {'TMUX_WEB_COOKIE_NAME':'invalid;cookie'}):
            with self.subTest(values=values), patch.dict(os.environ,values,clear=True):
                with self.assertRaises(ValueError):
                    RuntimeConfig.from_environment(Path(__file__).parent)

    def test_failed_persistence_keeps_previous_complete_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'state.json'
            path.write_text('{"version":1}')
            def interrupted(data,stream):
                stream.write('{')
                raise OSError('simulated write failure')
            with patch('hub.storage.json.dump',side_effect=interrupted):
                with self.assertRaises(OSError):
                    atomic_json(str(path),{'version':2})
            self.assertEqual(json.loads(path.read_text()),{'version':1})
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()),['state.json'])
            atomic_json(str(path),{'version':2})
            self.assertEqual(json.loads(path.read_text()),{'version':2})
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_target_parsing_never_depends_on_live_registry(self):
        self.assertEqual(split_target('offline:work'),('offline','work'))
        self.assertEqual(split_target('work'),(None,'work'))
        with self.assertRaises(ValueError):
            split_target('offline:')

    def test_full_output_queue_still_delivers_termination(self):
        queue=asyncio.Queue(maxsize=2)
        queue.put_nowait(b'old')
        queue.put_nowait(b'new')
        offer_output(queue,None)
        self.assertEqual(queue.get_nowait(),b'new')
        self.assertIsNone(queue.get_nowait())

    def test_candidate_cookie_does_not_accept_live_cookie(self):
        with patch.object(server,'COOKIE_NAME','tmux_web_b_token'), patch.object(server,'_TOKENS',{'candidate':time.time()+60}):
            self.assertFalse(server.request_authed(SimpleNamespace(headers={'Cookie':'tmux_web_token=candidate'})))
            self.assertTrue(server.request_authed(SimpleNamespace(headers={'Cookie':'tmux_web_token=production; tmux_web_b_token=candidate'})))


class IsolatedRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_detach_failure_cannot_skip_local_pty_cleanup(self):
        fake_os=SimpleNamespace(environ={},close=Mock(),kill=Mock(),waitpid=Mock())
        request=SimpleNamespace(request=SimpleNamespace(path='/ws?session=fixture'))
        loop=asyncio.get_running_loop()
        with patch.object(server,'os',fake_os), patch.object(server.pty,'fork',return_value=(12345,4567)), \
                patch.object(server,'request_authed',return_value=True), \
                patch.object(server,'web_attach'), patch.object(server,'set_winsize',side_effect=OSError('setup failed')), \
                patch.object(server,'web_detach',side_effect=subprocess.TimeoutExpired('fixture',1)), \
                patch.object(loop,'remove_reader'), patch.object(server.asyncio,'to_thread',new_callable=AsyncMock):
            with self.assertRaises(OSError):
                await server.handle_ws(request)
        fake_os.close.assert_called_once_with(4567)
        fake_os.kill.assert_called_once_with(12345,server.signal.SIGHUP)

    async def test_failed_remote_watch_cleans_registration(self):
        remote=SimpleNamespace(sid_by_name=lambda name:1, watchers={},send_json=AsyncMock(side_effect=ConnectionError('closed')))
        with patch.object(server,'web_attach'), patch.object(server,'web_detach') as detach:
            with self.assertRaises(ConnectionError):
                await server.handle_node_attach(SimpleNamespace(),remote,'fixture:session','session')
        self.assertEqual(remote.watchers,{})
        detach.assert_called_once()

    async def test_offline_node_operations_cannot_reach_local_tmux(self):
        with patch.object(server,'request_authed',return_value=True), patch.object(server,'NODES',{}), patch.object(server,'tmux') as local:
            for path in ('/api/kill?name=offline:work', '/api/send?name=offline:work&text=echo',
                         '/api/capture?name=offline:work', '/ws?session=offline:work'):
                with self.subTest(path=path):
                    response=await server.process_request(SimpleNamespace(),SimpleNamespace(path=path,headers={}))
                    self.assertEqual(response.status_code,404)
            local.assert_not_called()

    async def test_candidate_proxy_cannot_route_to_live_port(self):
        backend=SimpleNamespace(PORT=60001,BLOCKED_PORTS={59999},request_authed=lambda r:True)
        response=await http_frontend.proxy(SimpleNamespace(match_info={'port':'59999'}),backend)
        self.assertEqual(response.status,400)


if __name__ == '__main__':
    unittest.main()
