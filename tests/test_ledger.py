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


if __name__ == "__main__":
    unittest.main()
