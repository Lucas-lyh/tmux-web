import datetime
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import token_usage as codex
from hub import usage as kimi


class IncrementalUsageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.patch = patch.object(codex, "CODEX_HOME", str(self.root / "codex"))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        codex._cache.clear()
        codex._index = codex._Index()
        for cache in (kimi._token_cache, kimi._meta_cache, kimi._kimi_files,
                      kimi._kimi_totals, kimi._kimi_sessions, kimi._kimi_session_dirs):
            cache.clear()
        self.day = datetime.date.today().isoformat()

    def row(self, kind, payload, second=0):
        return {"type": kind, "payload": payload,
                "timestamp": self.day + "T12:00:%02d+00:00" % second}

    def meta(self, sid="fixture"):
        return self.row("session_meta", {"id": sid, "cwd": "/fixture/project"})

    def snapshot(self, amount, second=0):
        return self.row("event_msg", {"type": "token_count", "info": {
            "total_token_usage": {"input_tokens": amount, "output_tokens": amount // 10}}}, second)

    def detail(self, amount, total, response="r1", second=0):
        payload = {"thread_id": "fixture", "response_id": response,
                   "usage": {"input_tokens": amount, "output_tokens": amount // 10}}
        if total is not None:
            payload["thread_token_usage"] = {"input_tokens": total, "output_tokens": total // 10}
        return self.row("token_usage_record", payload, second)

    def codex_file(self, rows, name="a", archived=False):
        folder = "archived_sessions" if archived else "sessions"
        path = Path(codex.CODEX_HOME) / folder / (name + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return path

    def totals(self):
        result = codex.codex_sessions("2000-01-01")
        return {key: sum(day[key] for session in result for day in session["days"].values())
                for key in (*codex.TOKEN_KEYS, "steps")}

    def append(self, path, row):
        data = (json.dumps(row) + "\n").encode()
        with path.open("ab") as stream:
            stream.write(data)
        return len(data)

    def test_snapshot_before_detail_has_same_total_as_reverse_order(self):
        for rows in (
            [self.snapshot(100), self.snapshot(150), self.detail(50, 150)],
            [self.snapshot(100), self.detail(50, 150), self.snapshot(150)],
        ):
            with self.subTest(order=rows[1]["type"]):
                self.codex_file([self.meta(), *rows])
                total = self.totals()
                self.assertEqual((total["inputOther"], total["output"], total["steps"]), (150, 15, 2))

    def test_late_detail_only_subtracts_its_overlap_with_larger_snapshot(self):
        self.codex_file([self.meta(), self.snapshot(100), self.snapshot(200), self.detail(50, 150)])
        total = self.totals()
        self.assertEqual((total["inputOther"], total["output"], total["steps"]), (200, 20, 3))

    def test_cross_file_snapshots_and_details_are_reconciled(self):
        self.codex_file([self.meta(), self.snapshot(100)], archived=True)
        self.codex_file([self.meta(), self.detail(50, 100)], name="details")
        total = self.totals()
        self.assertEqual((total["inputOther"], total["output"], total["steps"]), (100, 10, 2))

    def test_reset_reuses_old_totals_in_new_epoch(self):
        self.codex_file([self.meta(), self.snapshot(100), self.snapshot(150),
                         self.snapshot(50), self.snapshot(100)])
        total = self.totals()
        self.assertEqual((total["inputOther"], total["output"], total["steps"]), (250, 25, 4))

    def test_detail_precedes_reset_snapshot(self):
        self.codex_file([self.meta(), self.snapshot(100, 1),
                         self.detail(50, 50, second=2), self.snapshot(50, 2)])
        total = self.totals()
        self.assertEqual((total["inputOther"], total["output"], total["steps"]), (150, 15, 2))

    def test_partial_file_after_reset_aligns_with_complete_snapshot_file(self):
        self.codex_file([self.meta(), self.snapshot(100, 1), self.snapshot(50, 2)], archived=True)
        self.codex_file([self.meta(), self.detail(50, 50, second=2)], name="detail")
        total = self.totals()
        self.assertEqual((total["inputOther"], total["output"], total["steps"]), (150, 15, 2))

    def test_late_pre_reset_detail_stays_in_old_epoch(self):
        self.codex_file([self.meta(), self.snapshot(100, 1), self.snapshot(50, 3),
                         self.detail(100, 100, response="late", second=1)])
        total = self.totals()
        self.assertEqual((total["inputOther"], total["output"]), (150, 15))

    def test_warm_and_append_queries_do_no_full_reparse_or_reaggregation(self):
        path = self.codex_file([self.meta()] + [self.snapshot(i * 10) for i in range(1, 2001)])
        self.totals()
        tail = codex._cache[str(path)]
        before = (tail.bytes_read, tail.parsed_lines, codex._index.applied_events)
        for _ in range(3):
            self.totals()
        self.assertEqual((tail.bytes_read, tail.parsed_lines, codex._index.applied_events), before)
        added = self.append(path, self.snapshot(20010))
        total = self.totals()
        self.assertEqual(total["inputOther"], 20010)
        self.assertEqual(tail.bytes_read - before[0], added)
        self.assertEqual(tail.parsed_lines - before[1], 1)
        self.assertEqual(codex._index.applied_events - before[2], 1)

    def test_partial_tail_replacement_truncation_and_deletion(self):
        path = self.codex_file([self.meta(), self.snapshot(100)])
        self.totals()
        encoded = (json.dumps(self.detail(50, 150)) + "\n").encode()
        with path.open("ab") as stream:
            stream.write(encoded[:30])
        self.assertEqual(self.totals()["inputOther"], 100)
        with path.open("ab") as stream:
            stream.write(encoded[30:])
        self.assertEqual(self.totals()["inputOther"], 150)
        replacement = path.with_suffix(".new")
        replacement.write_text(json.dumps(self.meta()) + "\n" + json.dumps(self.snapshot(20)) + "\n")
        replacement.replace(path)
        self.assertEqual(self.totals()["inputOther"], 20)
        path.write_text(json.dumps(self.meta()) + "\n")
        self.assertEqual(codex.codex_sessions("2000-01-01"), [])
        path.unlink()
        self.assertEqual(codex.codex_sessions("2000-01-01"), [])
        self.assertEqual(codex._cache, {})

    def test_malformed_codex_rows_do_not_discard_later_usage(self):
        bad = self.detail(10, 10)
        bad["payload"]["usage"]["input_tokens"] = True
        path = self.codex_file([self.meta(), bad, self.snapshot(100)])
        self.assertEqual(self.totals()["inputOther"], 100)
        self.assertEqual(codex._cache[str(path)].parse_errors, 1)

    def kimi_file(self, rows, session="fixture", agent="main"):
        path = self.root / "kimi" / "workspace" / ("session_" + session) / "agents" / agent / "wire.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return path

    def kimi_row(self, amount=10):
        return {"time": datetime.datetime.now().timestamp() * 1000,
                "event": {"usage": {"inputOther": amount, "output": 2}}}

    def kimi_day(self):
        return kimi._kimi_token_day(self.day, str(self.root / "kimi"))

    def test_kimi_type_errors_are_isolated_and_observable(self):
        good = self.kimi_row()
        rows = [
            {"event": [], "usage": "wrong", "time": 1},
            {"usage": {"inputOther": "10"}, "time": good["time"]},
            {"usage": {"output": True}, "time": good["time"]},
            {"usage": {"output": -1}, "time": good["time"]},
            {"usage": {"output": 1}, "time": "not a timestamp"},
            {"usage": {"output": 1}},
            good,
        ]
        self.kimi_file(rows)
        result = self.kimi_day()
        self.assertEqual(result["totals"]["inputOther"], 10)
        self.assertEqual(result["totals"]["steps"], 1)
        self.assertEqual(result["parse_errors"], 6)

    def test_kimi_incremental_partial_tail_and_direct_wire_cache(self):
        path = self.kimi_file([self.kimi_row()] * 1000)
        self.assertEqual(self.kimi_day()["totals"]["inputOther"], 10000)
        tail = kimi._token_cache[str(path)]
        before = (tail.bytes_read, tail.parsed_lines)
        self.kimi_day()
        self.assertEqual((tail.bytes_read, tail.parsed_lines), before)
        encoded = (json.dumps(self.kimi_row(7)) + "\n").encode()
        with path.open("ab") as stream:
            stream.write(encoded[:20])
        self.assertEqual(self.kimi_day()["totals"]["inputOther"], 10000)
        with path.open("ab") as stream:
            stream.write(encoded[20:])
        # A public compatibility read must not hide changes from the aggregate.
        kimi._wire_daily(str(path))
        self.assertEqual(self.kimi_day()["totals"]["inputOther"], 10007)
        self.assertEqual(tail.bytes_read - before[0], len(encoded))
        self.assertEqual(tail.parsed_lines - before[1], 1)

    def test_kimi_rotation_deletion_and_malformed_metadata(self):
        path = self.kimi_file([self.kimi_row(10)])
        metadata = path.parents[2] / "state.json"
        metadata.write_text(json.dumps({"title": [], "cwd": {"invalid": True}}))
        self.assertEqual(self.kimi_day()["sessions"][0]["title"], "")
        self.assertEqual(self.kimi_day()["sessions"][0]["cwd"], "")
        replacement = path.with_suffix(".new")
        replacement.write_text(json.dumps(self.kimi_row(3)) + "\n")
        replacement.replace(path)
        self.assertEqual(self.kimi_day()["totals"]["inputOther"], 3)
        path.unlink()
        result = self.kimi_day()
        self.assertEqual(result["sessions"], [])
        self.assertEqual(result["totals"]["inputOther"], 0)
        self.assertEqual(kimi._token_cache, {})
        self.assertEqual(kimi._meta_cache, {})


if __name__ == "__main__":
    unittest.main()
