import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import shape_verify


class ParseShapesTests(unittest.TestCase):
    def test_header_shapes_enumerated(self):
        shapes = shape_verify.parse_shapes()
        for q in ("albw::Id64", "albw::Flag16", "albw::PtrList", "albw::Factory",
                  "albw::StateMgr", "albw::Delegate", "sead::SafeStringBase",
                  "albw::randRange", "operator new"):
            self.assertIn(q, shapes)
        # helpers and plain typedefs are not shapes
        for q in ("albw::SmFunc", "albw::DelegateFn", "s64", "albw::invoke"):
            self.assertNotIn(q, shapes)
        self.assertEqual(shapes["albw::Id64"]["kind"], "struct")
        self.assertEqual(shapes["operator new"]["kind"], "operator")

    def test_site_regexes_include_structural_fallback(self):
        pats = shape_verify.site_regexes("albw::Delegate", "Delegate")
        self.assertTrue(any("virtual" in p for p in pats))
        pats = shape_verify.site_regexes("albw::Id64", "Id64")
        self.assertTrue(any(p == r"\bId64\b" for p in pats))


class VerdictTests(unittest.TestCase):
    def site(self, check, status="honest", tricks=None):
        return {"addr": "00000001", "path": "src/a.cpp", "status": status,
                "check": check, "tricks": tricks or []}

    def test_pass_needs_three_distinct_honest_matches(self):
        ent = {"sites": [self.site("MATCH"), self.site("MATCH"), self.site("MATCH")]}
        self.assertEqual(shape_verify.verdict_of(ent), "PASS")
        ent = {"sites": [self.site("MATCH"), self.site("MATCH")]}
        self.assertNotEqual(shape_verify.verdict_of(ent), "PASS")

    def test_hack_or_tricky_sites_do_not_count(self):
        ent = {"sites": [self.site("MATCH", status="hack"),
                         self.site("MATCH", tricks=["weak"]),
                         self.site("MATCH"), self.site("MATCH"), self.site("MATCH")]}
        self.assertEqual(shape_verify.verdict_of(ent), "PASS")  # 3 clean ones
        ent = {"sites": [self.site("MATCH", status="hack"), self.site("MATCH", tricks=["asm"]),
                         self.site("MATCH"), self.site("MATCH")]}
        self.assertEqual(shape_verify.verdict_of(ent), "FAIL")

    def test_pending_when_unchecked_sites_remain(self):
        ent = {"sites": [self.site("MATCH"), self.site(None), self.site(None)]}
        self.assertEqual(shape_verify.verdict_of(ent), "PENDING")


class LessonsBlockTests(unittest.TestCase):
    def report(self):
        return {"min_sites": 3, "verifier": "v9", "updated": "2026-11-14T00:00:00+00:00",
                "shapes": {"albw::Id64": {"kind": "struct", "name": "Id64", "verdict": "PASS", "sites": [
                    {"addr": "00000001", "path": "src/a.cpp", "status": "honest", "check": "MATCH", "tricks": []},
                    {"addr": "00000002", "path": "src/b.cpp", "status": "honest", "check": "MATCH", "tricks": []},
                    {"addr": "00000003", "path": "src/c.cpp", "status": "honest", "check": "MATCH", "tricks": []},
                ]}}}

    def test_block_renders_sites_and_markers(self):
        block = shape_verify.render_block(self.report())
        self.assertTrue(block.startswith(shape_verify.BLOCK_BEGIN))
        self.assertTrue(block.rstrip().endswith(shape_verify.BLOCK_END))
        self.assertIn("`albw::Id64` | PASS", block)
        self.assertIn("`00000001` (src/a.cpp)", block)

    def test_lessons_freshness_check_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lessons = root / "LESSONS.md"
            report = root / "shape_verification.json"
            report.write_text(json.dumps(self.report()))
            lessons.write_text("# L\n\n" + shape_verify.render_block(self.report()) + "\n")
            with patch.object(shape_verify, "ROOT", str(root)), \
                 patch.object(shape_verify, "REPORT", str(report)), \
                 patch.object(shape_verify, "LESSONS", str(lessons)):
                shape_verify.cmd_lessons(type("A", (), {"write": False})())  # current: no exit
                lessons.write_text("# L\n\nstale\n")
                with self.assertRaises(SystemExit):
                    shape_verify.cmd_lessons(type("A", (), {"write": False})())
                shape_verify.cmd_lessons(type("A", (), {"write": True})())
                self.assertIn(shape_verify.BLOCK_BEGIN, lessons.read_text())


if __name__ == "__main__":
    unittest.main()
