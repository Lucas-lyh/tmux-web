import datetime
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import token_usage as usage
import server


class TokenUsageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patch = patch.object(usage, 'CODEX_HOME', self.tmp.name)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        usage._cache.clear()

    def write(self, name, rows):
        path = os.path.join(self.tmp.name, 'sessions', name + '.jsonl')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            for row in rows:
                f.write(json.dumps(row) + '\n')
        return path

    def row(self, kind, payload, stamp='2026-09-06T12:00:00Z'):
        return dict(type=kind, payload=payload, timestamp=stamp)

    def meta(self, sid='a'):
        return self.row('session_meta', dict(id=sid, cwd='/project/demo'))

    def count(self, n, stamp='2026-09-06T12:00:00Z'):
        return self.row('event_msg', dict(type='token_count', info=dict(total_token_usage=n)), stamp)

    def test_legacy_duplicates_and_local_days(self):
        first = dict(input_tokens=100, cached_input_tokens=60, output_tokens=20, reasoning_output_tokens=10)
        second = dict(input_tokens=150, cached_input_tokens=90, output_tokens=30, reasoning_output_tokens=15)
        self.write('a', [self.meta(), self.count(first), self.count(first), self.count(second, '2026-09-07T12:00:00Z')])
        s = usage.codex_sessions('2026-09-01')[0]['days']
        self.assertEqual(s['2026-09-06'], dict(inputOther=40, inputCacheRead=60, inputCacheCreation=0, output=20, steps=1))
        self.assertEqual(s['2026-09-07']['inputOther'], 20)
        self.assertEqual(s['2026-09-07']['output'], 10)

    def test_records_and_legacy_in_same_file_and_fork(self):
        old = dict(input_tokens=100, cached_input_tokens=60, output_tokens=20)
        new = dict(input_tokens=50, cached_input_tokens=20, cache_write_input_tokens=10, output_tokens=10)
        total = dict(input_tokens=150, cached_input_tokens=80, cache_write_input_tokens=10, output_tokens=30)
        record = self.row('token_usage_record', dict(thread_id='a', response_id='r1', usage=new, thread_token_usage=total))
        self.write('a', [self.meta(), self.count(old), record, record, self.count(total), self.count(total)])
        self.write('b', [self.meta('b'), record])
        s = usage.codex_sessions('2026-09-01')
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]['days']['2026-09-06'], dict(inputOther=60, inputCacheRead=80, inputCacheCreation=10, output=30, steps=2))

    def test_partial_line_and_cache_refresh(self):
        path = self.write('a', [self.meta()])
        with open(path, 'a') as f:
            f.write('{"type":"event_msg"')
        self.assertEqual(usage.codex_sessions('2026-09-01'), [])
        self.write('a', [self.meta(), self.count(dict(input_tokens=10, output_tokens=2))])
        self.assertEqual(usage.codex_sessions('2026-09-01')[0]['days']['2026-09-06']['output'], 2)

    def test_provider_totals_and_day_details(self):
        today = datetime.date.today().isoformat()
        self.write('a', [self.meta(), self.count(dict(input_tokens=100, output_tokens=20), today+'T12:00:00+08:00')])
        with patch.object(server, 'KIMI_SESSIONS_DIR', self.tmp.name):
            k, c, a = [server.token_stats(1, source) for source in ('kimi', 'codex', 'all')]
            for key in usage.TOKEN_KEYS:
                self.assertEqual(a['days'][0][key], k['days'][0][key]+c['days'][0][key])
                self.assertEqual(server.token_day(today, 'all')['totals'][key], a['days'][0][key])
            self.assertEqual(server.token_day(today, 'all')['sessions'][0]['provider'], 'codex')


if __name__ == '__main__':
    unittest.main()
