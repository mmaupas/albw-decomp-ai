"""State vocabulary alignment (roadmap H8): the --json shapes of
`worklist report`/`status`, `refine` and the permuter carry the aligned
ecosystem fields (score/max_score, diff, flags_tried, permuter) ALONGSIDE
the pre-existing fields, which keep their names and semantics. Nothing is
renamed or dropped: score == frac == words/total (the word-match fraction),
max_score == 1.0, diff exposes the OP/REG/PERM class numerically, and the
field map is documented in docs/AUTOMATION_PLAN.md phase 10.
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
import refine
import worklist

ADDR = 0x100000
KEY = "%08X" % ADDR


class VocabularyFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "functions.json").write_text("{}")
        # refine history: two distinct flag sets checked for the fixture target
        hist = self.root / "logs" / "refine" / KEY
        hist.mkdir(parents=True)
        (hist / "history.jsonl").write_text(
            json.dumps({"iter": 0, "wave": "baseline", "flags": "-O3 -Otime", "match": False,
                        "n_op": 2, "n_reg": 1, "perm": False, "words": 8, "total": 10,
                        "sim": 80.0, "score": 0.8, "err": ""}) + "\n"
            + json.dumps({"iter": 0, "wave": "flags", "flags": "-O2", "match": False,
                          "n_op": 3, "n_reg": 0, "perm": False, "words": 7, "total": 10,
                          "sim": 70.0, "score": 0.7, "err": ""}) + "\n")
        # permuter tried-cache: one rejected candidate for the fixture target
        pdir = self.root / "logs" / "permuter"
        pdir.mkdir(parents=True)
        pkey = permuter.candidate_key("fixture source", ADDR, "4.1/b1049", "-O3 -Otime")
        (pdir / "tried.json").write_text(json.dumps({
            "version": 1, "stats": {"lookups": 4, "hits": 3},
            "entries": {pkey: {"outcome": "rejected", "addr": KEY, "cc": "4.1/b1049",
                               "flags": "-O3 -Otime", "words": 8, "total": 10, "score": 0.8,
                               "sim": 80.0, "err": "", "ts": "2026-01-01T00:00:00+00:00",
                               "run": "fixture", "skips": 3}}}))


class WorklistReportSchemaTests(VocabularyFixture):
    def report_rows(self):
        state = {"attempted": {KEY: {"status": "BUDGET"}, "00200000": {"status": "negative"}},
                 "registered": []}
        rstate = {"best": {"match": False, "n_op": 2, "n_reg": 1, "perm": False,
                           "words": 8, "total": 10, "sim": 80.0},
                  "used": 5, "origin": "synth:stores", "status": "BUDGET"}
        with patch.object(worklist, "ROOT", str(self.root)), patch.object(
                worklist, "load_state", return_value=state), patch.object(
                worklist, "load_status", return_value={}), patch.object(
                worklist, "refine_state", side_effect=lambda a: rstate if a == ADDR else None), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            worklist.report(as_json=True)
        return json.loads(out.getvalue())

    def test_report_rows_carry_old_and_new_fields_side_by_side(self):
        rows = self.report_rows()
        self.assertEqual(len(rows), 2)
        row = next(r for r in rows if r["addr"] == KEY)
        # pre-existing fields, unchanged names and semantics
        self.assertEqual(row["kind"], "OP=2 REG=1")
        self.assertEqual(row["frac"], 0.8)
        self.assertEqual(row["checks"], 5)
        self.assertEqual(row["origin"], "synth:stores")
        self.assertIn("budget exhausted", row["hypothesis"])
        # aligned fields, additive
        self.assertEqual(row["score"], row["frac"])
        self.assertEqual(row["max_score"], 1.0)
        self.assertEqual(row["diff"], {"op": 2, "reg": 1, "perm": False})
        self.assertEqual(row["flags_tried"], ["-O3 -Otime", "-O2"])
        self.assertEqual(row["permuter"]["entries"], 1)
        self.assertEqual(row["permuter"]["rejected"], 1)
        self.assertEqual(row["permuter"]["skips"], 3)
        self.assertEqual(row["permuter"]["best"]["outcome"], "rejected")
        self.assertEqual(row["permuter"]["best"]["score"], 0.8)

    def test_report_rows_without_refine_state_still_get_aligned_fields(self):
        rows = self.report_rows()
        row = next(r for r in rows if r["addr"] == "00200000")
        self.assertEqual(row["kind"], "negative")
        self.assertEqual(row["frac"], 0.0)
        self.assertEqual(row["score"], 0.0)
        self.assertEqual(row["max_score"], 1.0)
        self.assertEqual(row["flags_tried"], [])
        self.assertIsNone(row["permuter"])
        self.assertNotIn("checks", row)  # legacy row shape preserved

    def test_report_text_output_is_unchanged(self):
        state = {"attempted": {KEY: {"status": "BUDGET"}}, "registered": []}
        rstate = {"best": {"match": False, "n_op": 2, "n_reg": 1, "perm": False,
                           "words": 8, "total": 10, "sim": 80.0},
                  "used": 5, "origin": "synth:stores", "status": "BUDGET"}
        with patch.object(worklist, "ROOT", str(self.root)), patch.object(
                worklist, "load_state", return_value=state), patch.object(
                worklist, "load_status", return_value={}), patch.object(
                worklist, "refine_state", return_value=rstate), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            worklist.report()
        text = out.getvalue()
        self.assertIn("near-miss backlog (1, closest first):", text)
        self.assertRegex(text, r"00100000\s+OP=2 REG=1\s+80%")
        self.assertIn("NEXT  pick one:", text)

    def test_status_json_adds_permuter_hit_rate_alongside_old_counts(self):
        state = {"attempted": {}, "registered": []}
        with patch.object(worklist, "ROOT", str(self.root)), patch.object(
                worklist, "CAND_FILE", str(self.root / "nonexistent.txt")), patch.object(
                worklist, "load_state", return_value=state), patch.object(
                worklist, "refine_state", return_value=None), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            worklist.status_summary(as_json=True)
        s = json.loads(out.getvalue())
        self.assertEqual(s["candidates"], -1)
        self.assertEqual(s["attempted"], 0)
        self.assertEqual(s["registered"], 0)
        self.assertEqual(s["match_waiting"], 0)
        self.assertEqual(s["permuter"]["entries"], 1)
        self.assertEqual(s["permuter"]["lookups"], 4)
        self.assertEqual(s["permuter"]["hits"], 3)
        self.assertEqual(s["permuter"]["hit_rate"], 0.75)
        self.assertEqual(s["permuter"]["cache"], os.path.join("logs", "permuter", "tried.json"))


class RefineJsonSchemaTests(VocabularyFixture):
    def setUp(self):
        super().setUp()
        # the refine run appends its own history rows; start from a clean file
        # (the permuter tried.json fixture stays: it is per-address, not per-run)
        (self.root / "logs" / "refine" / KEY / "history.jsonl").unlink(missing_ok=True)

    def run_refine(self):
        source = self.root / "source.cpp"
        source.write_text('extern "C" void func_00100000() {}\n')
        with patch.object(refine, "ROOT", str(self.root)), patch.object(
                refine, "check_one", side_effect=lambda *a, **k: dict(
                    match=False, err="", words=8, total=10, sim=80.0, out="fixture")), \
                patch.object(refine, "classify", side_effect=lambda *a: dict(
                    n_op=2, n_reg=1, perm=False)), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            result = refine.run(ADDR, budget=1, src=str(source), as_json=True)
        return json.loads(out.getvalue()), result

    def test_refine_json_keeps_old_fields_and_adds_aligned_ones(self):
        summary, result = self.run_refine()
        # legacy top-level shape
        self.assertEqual(summary["addr"], KEY)
        self.assertEqual(summary["status"], "BUDGET")
        self.assertEqual(summary["used"], 1)
        self.assertEqual(summary["origin"], "src:%s" % (self.root / "source.cpp"))
        # legacy best fields, unchanged
        best = summary["best"]
        for field in ("n_op", "n_reg", "perm", "words", "total", "sim", "match", "flags", "err"):
            self.assertIn(field, best)
        self.assertEqual((best["n_op"], best["n_reg"], best["words"], best["total"], best["sim"]),
                         (2, 1, 8, 10, 80.0))
        # aligned fields, additive: score is the identical word fraction
        self.assertEqual(best["score"], 0.8)
        self.assertEqual(best["max_score"], 1.0)
        self.assertEqual(summary["score"], 0.8)
        self.assertEqual(summary["max_score"], 1.0)
        self.assertEqual(summary["flags_tried"], [best["flags"]])
        self.assertEqual(summary["permuter"]["entries"], 1)
        self.assertEqual(summary["permuter"]["best"]["run"], "fixture")
        # internal result object keeps its legacy shape for programmatic callers
        self.assertEqual(result["status"], "BUDGET")
        self.assertEqual(result["best"]["n_op"], 2)

    def test_refine_history_records_score_per_check(self):
        self.run_refine()
        hist = self.root / "logs" / "refine" / KEY / "history.jsonl"
        rows = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()]
        self.assertEqual(rows[0]["score"], 0.8)
        self.assertIn("flags", rows[0])

    def test_refine_defer_json_has_aligned_fields_without_best(self):
        with patch.object(refine, "ROOT", str(self.root)), patch.object(
                refine, "synth_start", return_value=(None, "no skeleton")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            result = refine.run(ADDR, start="synth", as_json=True)
        summary = json.loads(out.getvalue())
        self.assertIsNone(summary["best"])
        self.assertIsNone(summary["score"])
        self.assertEqual(summary["max_score"], 1.0)
        self.assertEqual(summary["flags_tried"], [])
        self.assertEqual(summary["permuter"]["entries"], 1)
        self.assertEqual(result["reason"], "no skeleton")


if __name__ == "__main__":
    unittest.main()
