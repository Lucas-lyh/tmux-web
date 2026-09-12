import asyncio
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

import server


class RuntimeLatencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_tmux_does_not_block_other_coroutines(self):
        started, release = threading.Event(), threading.Event()
        def slow(*args):
            started.set()
            if not release.wait(2):
                raise AssertionError('event loop did not release worker')
            return subprocess.CompletedProcess(args, 0, 'fixture', '')
        with patch.object(server, 'tmux', side_effect=slow):
            task = asyncio.create_task(server.tmux_async('fixture'))
            try:
                for _ in range(100):
                    if started.is_set():
                        break
                    await asyncio.sleep(.005)
                self.assertTrue(started.is_set())
                self.assertFalse(task.done())
            finally:
                release.set()
            self.assertEqual((await task).stdout, 'fixture')

    async def test_concurrent_stats_requests_share_one_nonblocking_sample(self):
        def slow():
            time.sleep(.08)
            return {'fixture': 1}
        with patch.object(server, '_STATS_CACHE', None), patch.object(server, '_STATS_TASK', None), \
                patch.object(server, '_STATS_AT', 0), patch.object(server, 'collect_stats', side_effect=slow) as collect:
            tasks = [asyncio.create_task(server.stats_snapshot()) for _ in range(10)]
            await asyncio.sleep(.01)
            self.assertFalse(any(task.done() for task in tasks))
            self.assertEqual(await asyncio.gather(*tasks), [{'fixture': 1}] * 10)
            self.assertEqual(await server.stats_snapshot(), {'fixture': 1})
            collect.assert_called_once()

    async def test_cancelled_tmux_command_keeps_session_serialization(self):
        started, release = threading.Event(), threading.Event()
        completed = []
        def command(label):
            if label == 'old':
                started.set()
                if not release.wait(2):
                    raise AssertionError('fixture worker not released')
            completed.append(label)
            return subprocess.CompletedProcess([], 0, '', '')
        @server.serialize_attach
        async def operation(name, label):
            await server.tmux_async(label)
        with patch.object(server, 'tmux', side_effect=command):
            old = asyncio.create_task(operation('fixture', 'old'))
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(.005)
            old.cancel()
            new = asyncio.create_task(operation('fixture', 'new'))
            await asyncio.sleep(.01)
            self.assertEqual(completed, [])
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await old
            await new
        self.assertEqual(completed, ['old', 'new'])


if __name__ == '__main__':
    unittest.main()
