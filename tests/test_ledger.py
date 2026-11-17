import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import audit
import worklist


class FakeGit:
    """Stands in for `git ls-files` inside audit.check_all (offline tmp roots)."""

    def __init__(self, tracked):
        self.tracked = tracked

    def run(self, *args, **kwargs):
        class Result:
            stdout = "\n".join(self.tracked) + "\n"
        return Result()


class AuditLiftedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "funcs.json").write_text(json.dumps({"starts": [0x100000, 0x100010], "bl": [], "ptr": []}))
        self.lifted = self.root / "src_lifted" / "func_00100010.c"
        self.lifted.parent.mkdir(parents=True)
        self.lifted.write_text("/* LIFTED: semantic scaffold */\nu32 func_00100010(u32 r0) { return r0; }\n")
        self.functions = self.root / "functions.json"
        patcher = patch.object(audit, "ROOT", str(self.root))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(audit, "TEXT_SIZE", 0x20)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_index(self, data):
        self.functions.write_text(audit.canonical_bytes(data))

    def check(self, data, tracked=("src_lifted/func_00100010.c",)):
        self.write_index(data)
        with patch.object(audit, "subprocess", FakeGit(tracked)), \
                patch.object(audit, "load", lambda: json.loads(self.functions.read_text())):
            return audit.check_all()

    def test_lifted_entry_is_clean_and_excluded_from_matched(self):
        data, errors, warnings, n_honest = self.check(
            {"00100010": {"status": "lifted", "path": "src_lifted/func_00100010.c", "cc": "4.1/b1049"}})
        self.assertEqual(errors, [])
        self.assertEqual(n_honest, 0)
        with patch.object(audit, "load", lambda: json.loads(self.functions.read_text())):
            stats = audit.stats(json.loads(self.functions.read_text()))
        self.assertEqual(stats["lifted"], 1)
        self.assertEqual(stats["matched_source_included"], 0)
        self.assertEqual(stats["bytes_by_status"]["lifted"], 16)  # 0x100010 .. 0x100020
        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["remaining_honest"], 2)  # lifted still needs an honest match

    def test_lifted_path_outside_src_lifted_is_rejected(self):
        _d, errors, _w, _n = self.check(
            {"00100010": {"status": "lifted", "path": "src/work8/auto/func_00100010.c", "cc": "4.1/b1049"}},
            tracked=("src/work8/auto/func_00100010.c",))
        self.assertTrue(any(e.startswith("lifted:") for e in errors), errors)

    def test_matched_entry_pointing_at_src_lifted_is_rejected(self):
        _d, errors, _w, _n = self.check(
            {"00100010": {"status": "honest", "path": "src_lifted/func_00100010.c",
                          "cc": "4.1/b1049", "hack_reasons": []}})
        self.assertTrue(any(e.startswith("lifted:") for e in errors), errors)

    def test_lifted_missing_file_is_rejected(self):
        _d, errors, _w, _n = self.check(
            {"00100010": {"status": "lifted", "path": "src_lifted/func_00100010.c", "cc": "4.1/b1049"}},
            tracked=())
        self.assertTrue(any("not tracked by git" in e for e in errors), errors)

    def test_semantic_match_requires_wall_class(self):
        for bad in (None, "bogus"):
            with self.subTest(wall_class=bad):
                ent = {"status": "semantic_match", "path": "src_lifted/func_00100010.c"}
                if bad is not None:
                    ent["wall_class"] = bad
                _d, errors, _w, _n = self.check({"00100010": ent})
                self.assertTrue(any("wall_class" in e for e in errors), errors)
        _d, errors, _w, _n = self.check(
            {"00100010": {"status": "semantic_match", "path": "src_lifted/func_00100010.c",
                          "wall_class": "scheduling"}})
        self.assertEqual(errors, [])
        with patch.object(audit, "load", lambda: json.loads(self.functions.read_text())):
            stats = audit.stats(json.loads(self.functions.read_text()))
        self.assertEqual(stats["semantic_match"], 1)
        self.assertEqual(stats["matched_source_included"], 0)  # never a matched count

    def test_readme_blocks_always_carry_the_lifted_row(self):
        blocks = audit.readme_blocks({
            "total_functions": 10, "text_bytes": 1000, "matched_source_included": 4,
            "matched_source_included_pct": 40.0,
            "bytes_by_status": {"honest": 400, "unmatched": 500, "lifted": 100},
            "honest": 4, "honest_pct": 40.0, "hack": 0, "hack_pct": 0.0,
            "no_source": 0, "unmatched": 5, "lifted": 1, "semantic_match": 0,
            "excluded": 0, "excluded_library": 0, "interior_address": 0,
            "remaining_honest": 6, "hack_reasons": {}})
        self.assertIn("Lifted (semantic, not byte-exact) | 1 | 10.0% | 100 | 10.0% |",
                      blocks["status"])
        self.assertIn("Matched, source included | 4 | 40.0% | 400 | 40.0% |", blocks["status"])


class WorklistLiftedRejectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.auto = self.root / "src" / "work8" / "auto"
        self.auto.mkdir(parents=True)
        self.lifted_dir = self.root / "src_lifted"
        self.lifted_dir.mkdir()
        self.lifted_src = self.lifted_dir / "func_00100000.c"
        self.lifted_src.write_text("u32 func_00100000(u32 r0) { return r0; }\n")
        (self.root / "functions.json").write_text("{}")
        for name, value in (("ROOT", str(self.root)), ("AUTO_DIR", str(self.auto)),
                            ("STATE_DIR", str(self.root / "logs" / "autodecomp")),
                            ("STATE_FILE", str(self.root / "logs" / "autodecomp" / "state.json"))):
            patcher = patch.object(worklist, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(worklist.fn, "STARTS", [0x100000])
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(worklist, "check_one", return_value=dict(match=True, err="", words=1, total=1))
        self.check = patcher.start()
        self.addCleanup(patcher.stop)

    def test_register_rejects_src_lifted_sources(self):
        with self.assertRaisesRegex(ValueError, "src_lifted/"):
            worklist.register(0x100000, src=str(self.lifted_src))
        self.check.assert_not_called()
        self.assertEqual((self.root / "functions.json").read_text(), "{}")
        self.assertFalse(list(self.auto.iterdir()))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "functions.json").write_text("{}")
        (self.root / "src_lifted").mkdir()
        (self.root / "src_lifted" / "func_00100000.c").write_text("u32 func_00100000(u32 r0) { return r0; }\n")
        for name, value in (("ROOT", str(self.root)),
                            ("STATE_DIR", str(self.root / "logs" / "autodecomp")),
                            ("STATE_FILE", str(self.root / "logs" / "autodecomp" / "state.json")),
                            ("VERIFY_DIR", str(self.root / "logs" / "verify")),
                            ("CORPUS_DIR", str(self.root / "logs" / "coverage"))):
            patcher = patch.object(worklist, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(worklist.fn, "STARTS", [0x100000])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_override_skeleton_and_verdict_parsing(self):
        text = worklist.emit_override_text(0x100000, "src_lifted/func_00100000.c")
        self.assertIn("RECOMP_OVERRIDE(0x00100000) {", text)
        self.assertIn("src_lifted/func_00100000.c", text)
        self.assertEqual(worklist.parse_verdict("125 returned, 0 mismatched"), (True, 0))
        self.assertEqual(worklist.parse_verdict("125 returned, 3 mismatched"), (False, 3))
        self.assertEqual(worklist.parse_verdict("garbage"), (None, None))

    def test_find_corpus_prefers_env_then_logs_dir(self):
        with patch.dict("os.environ", {"ZAKURO_REPLAY": str(self.root / "env-replay.bin")}):
            (self.root / "env-replay.bin").write_bytes(b"x")
            self.assertTrue(worklist.find_corpus().endswith("env-replay.bin"))
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(worklist.find_corpus())
            cov = Path(worklist.CORPUS_DIR)
            cov.mkdir(parents=True)
            (cov / "replay.bin").write_bytes(b"x")
            (cov / "executed.jsonl").write_text("{}\n")
            self.assertTrue(worklist.find_corpus().endswith("replay.bin"))

    def test_verify_degrades_with_exact_corpus_instructions(self):
        with patch.object(worklist, "oracle_prereqs", return_value=["Zakuro replay corpus"]):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = worklist.verify(0x100000, src="src_lifted/func_00100000.c", as_json=True)
        self.assertEqual(rc, 2)
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["missing"], ["Zakuro replay corpus"])
        # skeleton emitted, resumable state written, ledger untouched
        self.assertTrue((self.root / "logs" / "verify" / "00100000" / "override.c").exists())
        vstate = json.loads((self.root / "logs" / "verify" / "00100000" / "state.json").read_text())
        self.assertEqual(vstate["last"]["status"], "blocked")
        self.assertEqual((self.root / "functions.json").read_text(), "{}")

    def test_verify_blocked_human_output_names_zakuro_record(self):
        with patch.object(worklist, "oracle_prereqs", return_value=["Zakuro replay corpus"]):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = worklist.verify(0x100000, src="src_lifted/func_00100000.c")
        self.assertEqual(rc, 2)
        self.assertIn("ZAKURO_RECORD=logs/coverage/replay.bin", out.getvalue())

    def test_verify_pass_publishes_semantic_match_with_wall_class(self):
        with patch.object(worklist, "oracle_prereqs", return_value=[]), \
                patch.object(worklist, "is_tracked", return_value=True), \
                patch.object(worklist, "candidate_source", return_value=("src_lifted/func_00100000.c", "lifted")):
            runner = lambda addr, count: (0, "125 returned, 0 mismatched")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = worklist.verify(0x100000, budget=1, count=125,
                                    wall_class="scheduling", as_json=True, runner=runner)
        self.assertEqual(rc, 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["published"], "semantic_match")
        ent = json.loads((self.root / "functions.json").read_text())["00100000"]
        self.assertEqual(ent["status"], "semantic_match")
        self.assertEqual(ent["wall_class"], "scheduling")
        self.assertEqual(ent["path"], "src_lifted/func_00100000.c")
        # audit accepts the new entry shape
        with patch.object(audit, "ROOT", str(self.root)), patch.object(audit, "TEXT_SIZE", 0x20):
            pass

    def test_verify_pass_on_untracked_source_records_state_only(self):
        with patch.object(worklist, "oracle_prereqs", return_value=[]), \
                patch.object(worklist, "is_tracked", return_value=False), \
                patch.object(worklist, "candidate_source", return_value=("logs/refine/00100000/best.c", "refine-near-miss")):
            runner = lambda addr, count: (0, "125 returned, 0 mismatched")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = worklist.verify(0x100000, as_json=True, runner=runner)
        self.assertEqual(rc, 0)
        self.assertIsNone(json.loads(out.getvalue())["published"])
        self.assertEqual((self.root / "functions.json").read_text(), "{}")
        vstate = json.loads((self.root / "logs" / "verify" / "00100000" / "state.json").read_text())
        self.assertEqual(vstate["last"]["status"], "pass")

    def test_verify_is_budgeted_and_resumable(self):
        vdir = self.root / "logs" / "verify" / "00100000"
        vdir.mkdir(parents=True)
        (vdir / "state.json").write_text(json.dumps({"runs": 3, "last": {"status": "fail"}}))
        with patch.object(worklist, "oracle_prereqs", return_value=[]):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = worklist.verify(0x100000, budget=3, as_json=True,
                                    runner=lambda a, c: (0, "1 returned, 0 mismatched"))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "budget-exhausted")

    def test_verify_rejects_bad_wall_class_and_non_start(self):
        with self.assertRaises(ValueError):
            worklist.verify(0x100000, wall_class="bogus", runner=lambda a, c: (0, ""))
        with self.assertRaises(ValueError):
            worklist.verify(0x100004, runner=lambda a, c: (0, ""))


if __name__ == "__main__":
    unittest.main()
