"""Tried-memory (roadmap H7): permuter.py must not re-compile candidates it has
already rejected in a previous run.

logs/permuter/tried.json keys are SHA-256 over the normalized candidate source
(comments/whitespace stripped) + target address + cc + flags; a later run skips
known-rejected entries, logs the skip count, and `status` reports the hit rate.
--fresh bypasses the cache. The cache only prevents wasted work: it never
invents candidates and never skips a recorded match.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import permuter

ADDR = 0x100000
KEY = "%08X" % ADDR
CC = "4.1/b1049"
FLAGS = "--cpu=MPCore -O3"


class NormalizeKeyTests(unittest.TestCase):
    def test_normalization_ignores_comments_and_whitespace_churn(self):
        base = permuter.normalize_source("int f(int a) { return a + 1; } // one\n")
        self.assertEqual(base, permuter.normalize_source(
            "int  f ( int a ) {\n  /* one */ return a+1;\n}\n"))
        self.assertEqual(base, permuter.normalize_source(
            "int f(int a) { /* multi\n   line\n   comment */ return a + 1; }"))

    def test_normalization_keeps_code_meaning(self):
        self.assertNotEqual(permuter.normalize_source("return a + 1;"),
                            permuter.normalize_source("return a - 1;"))

    def test_string_literals_are_kept_verbatim(self):
        a = permuter.normalize_source('const char* s = "a  b"; // note\n')
        self.assertEqual(a, permuter.normalize_source('const char* s="a  b";'))
        self.assertNotEqual(a, permuter.normalize_source('const char* s="a b";'))

    def test_key_depends_on_normalized_source_addr_cc_and_flags(self):
        k = permuter.candidate_key("src", ADDR, CC, FLAGS)
        self.assertEqual(len(k), 64)
        self.assertEqual(k, permuter.candidate_key("src // cosmetic\n", ADDR, CC, FLAGS))
        for other in (("src!", ADDR, CC, FLAGS), ("src", ADDR + 1, CC, FLAGS),
                      ("src", ADDR, "4.1/b894", FLAGS), ("src", ADDR, CC, "-O2")):
            self.assertNotEqual(k, permuter.candidate_key(*other))


class TriedCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "functions.json").write_text("{}")
        self.workdir = self.root / "work"
        self.workdir.mkdir()
        self.spec = self.root / "spec.py"
        self.rejected_key = permuter.candidate_key("rejected source", ADDR, CC, FLAGS)
        self.fixture_cache()

    def fixture_cache(self, entries=None):
        entries = entries if entries is not None else {
            self.rejected_key: {"outcome": "rejected", "addr": KEY, "cc": CC, "flags": FLAGS,
                                "words": 3, "total": 10, "score": 0.3, "sim": 30.0, "err": "",
                                "ts": "2026-01-01T00:00:00+00:00", "run": "fixture-run"}}
        os.makedirs(self.root / "logs" / "permuter", exist_ok=True)
        (self.root / "logs" / "permuter" / "tried.json").write_text(json.dumps(
            {"version": 1, "stats": {"lookups": 0, "hits": 0}, "entries": entries}))

    def write_spec(self, template, grid=None, flags=None):
        self.spec.write_text(
            "TEMPLATE = %r\nGRID = %r\n%s" % (template, grid or {},
                                             "FLAGS = %r\n" % flags if flags else ""))

    def run_main(self, *extra, check_side_effect=None):
        def fake_check(*args, **kwargs):
            if check_side_effect:
                return check_side_effect(*args, **kwargs)
            raise AssertionError("tried-cache should have skipped this candidate")
        with patch.object(permuter, "ROOT", str(self.root)), patch.object(
                permuter.tempfile, "mkdtemp", return_value=str(self.workdir)), patch.object(
                sys, "argv", ["permuter", KEY, str(self.spec), *extra]), patch.object(
                permuter, "check_one", side_effect=fake_check) as check, contextlib.redirect_stdout(
                io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            permuter.main()
        return out.getvalue(), check

    def cache(self):
        return json.loads((self.root / "logs" / "permuter" / "tried.json").read_text())

    def test_rejected_fixture_is_skipped_without_a_compile(self):
        self.write_spec("rejected source", flags=[FLAGS])
        text, check = self.run_main()
        check.assert_not_called()
        self.assertIn("skipped 1 known-rejected", text)
        self.assertIn("cached 3/10", text)
        cache = self.cache()
        self.assertEqual(cache["stats"]["lookups"], 1)
        self.assertEqual(cache["stats"]["hits"], 1)
        self.assertEqual(cache["entries"][self.rejected_key]["skips"], 1)
        self.assertEqual(cache["entries"][self.rejected_key]["run"], "fixture-run")

    def test_skip_persists_across_runs_and_keeps_the_recorded_score(self):
        self.write_spec("rejected source", flags=[FLAGS])
        self.run_main()
        text, check = self.run_main()
        check.assert_not_called()
        self.assertIn("skipped 1 known-rejected", text)
        cache = self.cache()
        self.assertEqual((cache["stats"]["lookups"], cache["stats"]["hits"]), (2, 2))
        self.assertEqual(cache["entries"][self.rejected_key]["words"], 3)
        self.assertEqual(cache["entries"][self.rejected_key]["skips"], 2)

    def test_cosmetic_edit_of_a_rejected_source_still_hits_the_cache(self):
        self.write_spec("rejected source  // reformatted\n", flags=[FLAGS])
        _text, check = self.run_main()
        check.assert_not_called()

    def test_fresh_bypasses_the_cache_and_rerecords(self):
        self.write_spec("rejected source", flags=[FLAGS])
        calls = []

        def fake_check(*args, **kwargs):
            calls.append(args)
            return dict(match=False, err="", words=4, total=10, sim=40.0, out="")

        _text, check = self.run_main("--fresh", check_side_effect=fake_check)
        self.assertEqual(check.call_count, 1)
        cache = self.cache()
        self.assertEqual(cache["stats"]["hits"], 0)  # bypassed: no skip counted
        self.assertEqual(cache["entries"][self.rejected_key]["words"], 4)
        self.assertNotEqual(cache["entries"][self.rejected_key]["run"], "fixture-run")

    def test_new_candidates_are_checked_and_recorded(self):
        # template "rejected {SLOT}" with SLOT=a normalizes to "rejected a",
        # which is NOT the fixture key ("rejected source") -> must be compiled
        self.spec.write_text('TEMPLATE = "rejected {SLOT}"\nGRID = {"SLOT": ["a"]}\nFLAGS = %r\n' % [FLAGS])
        seen = []

        def fake_check(*args, **kwargs):
            seen.append(args)
            return dict(match=False, err="", words=1, total=10, sim=10.0, out="")

        _text, _check = self.run_main(check_side_effect=fake_check)
        self.assertEqual(len(seen), 1)
        cache = self.cache()
        self.assertEqual(len(cache["entries"]), 2)
        new_key = permuter.candidate_key("rejected a", ADDR, CC, FLAGS)
        self.assertIn(new_key, cache["entries"])
        entry = cache["entries"][new_key]
        self.assertEqual(entry["outcome"], "rejected")
        self.assertEqual(entry["addr"], KEY)
        self.assertEqual(entry["cc"], CC)
        self.assertEqual(entry["flags"], FLAGS)
        self.assertIn("ts", entry)
        self.assertIn("run", entry)
        self.assertEqual(entry["score"], 0.1)

    def test_recorded_match_is_never_skipped(self):
        match_key = permuter.candidate_key("winner source", ADDR, CC, FLAGS)
        self.fixture_cache(entries={match_key: {
            "outcome": "match", "addr": KEY, "cc": CC, "flags": FLAGS,
            "words": 10, "total": 10, "score": 1.0, "sim": 100.0, "err": "",
            "ts": "2026-01-01T00:00:00+00:00", "run": "fixture-run"}})
        self.write_spec("winner source", flags=[FLAGS])
        seen = []

        def fake_check(*args, **kwargs):
            seen.append(args)
            return dict(match=True, err="", words=10, total=10, sim=100.0, out="")

        self.run_main(check_side_effect=fake_check)
        self.assertEqual(len(seen), 1)  # matches are re-checked, never skipped

    def test_json_run_summary_carries_aligned_fields_and_cache_stats(self):
        self.write_spec("rejected source", flags=[FLAGS])
        out, check = self.run_main("--json")
        check.assert_not_called()
        summary = json.loads(out)  # stdout is exactly one JSON value
        self.assertEqual(summary["addr"], KEY)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["checks"], 0)
        self.assertEqual(summary["flags_tried"], [FLAGS])
        self.assertIn("run_id", summary)
        result = summary["results"][0]
        self.assertEqual(result["score"], 0.3)
        self.assertEqual(result["max_score"], 1.0)
        self.assertTrue(result["skipped"])
        self.assertEqual(summary["best"]["words"], 3)
        perm = summary["permuter"]
        self.assertEqual(perm["entries"], 1)
        self.assertEqual(perm["hits"], 1)
        self.assertEqual(perm["lookups"], 1)
        self.assertEqual(perm["hit_rate"], 1.0)
        self.assertEqual(perm["cache"], os.path.join("logs", "permuter", "tried.json"))

    def test_status_reports_hit_rate(self):
        self.write_spec("rejected source", flags=[FLAGS])
        self.run_main()
        self.run_main()
        with patch.object(permuter, "ROOT", str(self.root)), contextlib.redirect_stdout(io.StringIO()) as out:
            result = permuter.status(as_json=True)
        printed = json.loads(out.getvalue())
        self.assertEqual(printed, result)
        self.assertEqual(result["entries"], 1)
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(result["lookups"], 2)
        self.assertEqual(result["hits"], 2)
        self.assertEqual(result["hit_rate"], 1.0)
        self.assertEqual(result["skips"], 2)
        with contextlib.redirect_stdout(io.StringIO()) as text_out:
            permuter.status(root=str(self.root))
        self.assertIn("hit rate 100.0%", text_out.getvalue())

    def test_state_for_addr_surfaces_outcome_per_function(self):
        self.write_spec("rejected source", flags=[FLAGS])
        self.run_main()
        with patch.object(permuter, "ROOT", str(self.root)):
            state = permuter.state_for_addr(KEY)
            self.assertIsNone(permuter.state_for_addr("00ABCDEF"))
        self.assertEqual(state["entries"], 1)
        self.assertEqual(state["rejected"], 1)
        self.assertEqual(state["best"]["outcome"], "rejected")
        self.assertEqual(state["best"]["score"], 0.3)
        self.assertEqual(state["best"]["run"], "fixture-run")

    def test_corrupt_cache_file_starts_empty(self):
        (self.root / "logs" / "permuter" / "tried.json").write_text("{not json")
        with patch.object(permuter, "ROOT", str(self.root)):
            tried = permuter.load_tried()
        self.assertEqual(tried["entries"], {})
        self.assertEqual(tried["stats"], {"lookups": 0, "hits": 0})


if __name__ == "__main__":
    unittest.main()
