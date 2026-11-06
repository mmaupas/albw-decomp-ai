import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import permuter
import refine
import sweep
import worklist


class RefineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "functions.json").write_text("{}")
        self.source = self.root / "source.cpp"
        self.source.write_text('extern "C" void func_00100000() {}\n')
        self.visited = []
        self.winner = None
        for patcher in (
                patch.object(refine, "ROOT", str(self.root)),
                patch.object(refine, "gen_order", return_value=["first", "second", "third"]),
                patch.object(refine, "check_one", side_effect=self.fake_check),
                patch.object(refine, "classify", side_effect=lambda *args: dict(
                    n_op=0, n_reg=2, perm=False))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def fake_check(self, directory, source, addr, flags, sym, **kwargs):
        text = Path(source).read_text()
        self.visited.append((text, source, kwargs.get("cc")))
        match = text == self.winner
        return dict(match=match, err="", words=2 if match else 1,
                    total=2, sim=100 if match else 50, out="fixture")

    def run_refine(self, budget, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = refine.run(0x100000, budget=budget, src=str(self.source),
                                as_json=True, **kwargs)
        self.assertEqual(json.loads(output.getvalue())["status"], result["status"])
        return result

    def state(self):
        return json.loads((self.root / "logs/refine/00100000/state.json").read_text())

    def test_budget_resume_finishes_remaining_wave(self):
        self.winner = "third"
        self.assertEqual(self.run_refine(2)["status"], "BUDGET")
        state = self.state()
        self.assertEqual(state["pending"]["cursor"], 1)
        self.assertNotIn("order", state["tried"])
        self.assertEqual(self.run_refine(4)["status"], "MATCH")
        self.assertEqual([v[0] for v in self.visited][1:], ["first", "second", "third"])
        self.assertTrue(all(path.endswith(".cpp") for _, path, _ in self.visited))
        self.assertEqual((self.root / "logs/refine/00100000/best.cpp").read_text(), "third")

    def test_resume_repairs_stale_winner_copy(self):
        self.run_refine(1)
        best = self.root / "logs/refine/00100000/best.cpp"
        best.write_text("stale or interrupted copy")
        self.run_refine(1)
        self.assertEqual(best.read_text(), self.source.read_text())

    def test_legacy_checkpoint_is_not_trusted(self):
        self.run_refine(1)
        state_path = self.root / "logs/refine/00100000/state.json"
        state = self.state()
        state.pop("verifier")
        state_path.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, "legacy checkpoint"):
            self.run_refine(2)

    def test_defer_is_saved_and_is_valid_json(self):
        with patch.object(refine, "synth_start", return_value=(None, "no skeleton")):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                result = refine.run(0x100000, start="synth", as_json=True)
        self.assertEqual(json.loads(output.getvalue())["status"], "DEFER")
        self.assertEqual(result["reason"], "no skeleton")
        self.assertIsNone(self.state()["best"])

    def test_interrupted_baseline_does_not_exceed_exhausted_budget(self):
        with patch.object(refine, "check_one", side_effect=RuntimeError("interrupted")):
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                self.run_refine(1)
        self.assertEqual(self.state()["used"], 1)
        self.assertIsNone(self.state()["best"])
        self.assertEqual(self.run_refine(1)["status"], "BUDGET")
        self.assertEqual(self.state()["used"], 1)
        self.assertEqual(self.visited, [])
        self.run_refine(2)
        self.assertEqual(len(self.visited), 1)

    def test_twin_fallback_resumes_after_budget_boundary(self):
        twin = dict(text="poor twin", flags="--donor-fpic", cc="4.1/b894",
                    name="func_00100000", origin="twin:donor.cpp")
        self.winner = "skeleton"
        with patch.object(refine, "twin_start", return_value=twin), patch.object(
                refine, "classify", return_value=dict(n_op=4, n_reg=0, perm=False)), patch.object(
                refine, "synth_start", return_value=("skeleton", "synth:stores")) as synth, contextlib.redirect_stdout(io.StringIO()):
            first = refine.run(0x100000, budget=1, as_json=True)
            synth.assert_not_called()
            self.assertEqual(first["status"], "BUDGET")
            self.assertEqual(self.state()["fallback"], "pending")
            resumed = refine.run(0x100000, budget=2, as_json=True)
        self.assertEqual(resumed["status"], "MATCH")
        self.assertEqual([text for text, _, _ in self.visited], ["poor twin", "skeleton"])
        synth.assert_called_once()
        self.assertEqual(self.state()["fallback"], "done")

    def test_unspecified_target_settings_use_defaults_not_donor(self):
        twin = dict(text="donor", flags="--donor-fpic", cc="4.1/b894",
                    name="func_00100000", origin="twin:donor.cpp")
        with patch.object(refine, "twin_start", return_value=twin), contextlib.redirect_stdout(io.StringIO()):
            refine.run(0x100000, budget=1, as_json=True)
        self.assertEqual(self.visited[0][2], refine.fn.DEFAULT_CC)
        self.assertEqual(self.state()["flags_base"], refine.fn.DEFAULT_FLAGS)

    def test_recorded_target_build_settings_are_used(self):
        (self.root / "functions.json").write_text(json.dumps({
            "00100000": {"cc": "4.1/b894", "flags": "--apcs=/fpic"}}))
        self.run_refine(1)
        self.assertEqual(self.visited[0][2], "4.1/b894")
        self.assertEqual(self.state()["best"]["flags"], "--apcs=/fpic")

    def test_fresh_run_does_not_overwrite_previous_checked_variant(self):
        self.run_refine(1)
        old_path = Path(self.visited[0][1])
        old_source = old_path.read_text()
        self.source.write_text("new baseline")
        self.run_refine(1, fresh=True)
        self.assertNotEqual(self.visited[-1][1], str(old_path))
        self.assertEqual(old_path.read_text(), old_source)


class SweepTests(unittest.TestCase):
    def test_parallel_requests_are_rejected_before_loading_spec(self):
        for tool in (permuter, sweep):
            with self.subTest(tool=tool.__name__), patch.object(
                    sys, "argv", [tool.__name__, "00100000", "nonexistent.py", "--jobs", "2"]):
                with self.assertRaisesRegex(SystemExit, "Only --jobs 1"):
                    tool.main()

    def test_default_settings_and_unique_workspaces_with_fake_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "functions.json").write_text(json.dumps({"00100000": {
                "cc": "4.1/b894", "flags": "--recorded-fpic"}}))
            spec = root / "fixture.py"
            spec.write_text('TEMPLATE = "fixture"\nGRID = {}\n')
            workspaces = []

            def workspace(**kwargs):
                path = root / (kwargs["prefix"] + str(len(workspaces)))
                path.mkdir()
                workspaces.append(path)
                return str(path)

            for tool in (permuter, sweep):
                with self.subTest(tool=tool.__name__), patch.object(tool, "ROOT", str(root)), patch.object(
                        tool.tempfile, "mkdtemp", side_effect=workspace), patch.object(
                        sys, "argv", [tool.__name__, "00100000", str(spec)]), patch.object(
                        tool, "check_one", side_effect=lambda *args, **kwargs: dict(
                            match=False, err="fake oracle", words=0, total=1, sim=0, out="")) as check, contextlib.redirect_stdout(io.StringIO()):
                    tool.main()
                    tool.main()
                    self.assertEqual(check.call_count, 2)
                    self.assertEqual(check.call_args.args[3], "--recorded-fpic")
                    self.assertEqual(check.call_args.kwargs["cc"], "4.1/b894")
            self.assertEqual(len(set(workspaces)), 4)
            self.assertTrue(all(path.exists() for path in workspaces))


class ProcessTests(unittest.TestCase):
    def test_failed_child_cannot_claim_match(self):
        process = Mock(returncode=1)
        process.communicate.return_value = ("RESULT: MATCH 1/1 words (100.0%) similarity 100.0%", None)
        with patch.object(permuter.subprocess, "Popen", return_value=process) as popen:
            result = permuter.check_one("unused", "fixture.c", 0x100000, "--flags", None,
                                        cc="4.1/b894")
        self.assertFalse(result["match"])
        self.assertIn("CHECK FAILED", result["err"])
        args = popen.call_args.args[0]
        self.assertEqual(args[0], sys.executable)
        self.assertEqual(args[args.index("--cc") + 1], "4.1/b894")

    def test_final_result_wins_over_diagnostic_text(self):
        process = Mock(returncode=0)
        process.communicate.return_value = (
            "RESULT: MATCH 1/1 words (100.0%) similarity 100.0%\n"
            "RESULT: NO MATCH 0/1 words (0.0%) similarity 0.0%\n", None)
        with patch.object(permuter.subprocess, "Popen", return_value=process):
            result = permuter.check_one("unused", "fixture.c", 0x100000, "flags", None)
        self.assertFalse(result["match"])

    def test_inconsistent_match_summary_is_rejected(self):
        process = Mock(returncode=0)
        process.communicate.return_value = ("RESULT: MATCH 0/1 words (0.0%) similarity 0.0%", None)
        with patch.object(permuter.subprocess, "Popen", return_value=process):
            result = permuter.check_one("unused", "fixture.c", 0x100000, "flags", None)
        self.assertEqual(result["err"], "INVALID CHECK RESULT")

    def test_timeout_reaps_process(self):
        process = Mock(pid=1234)
        process.communicate.side_effect = [subprocess.TimeoutExpired("fixture", 1), ("", None)]
        with patch.object(permuter.subprocess, "Popen", return_value=process), patch.object(
                permuter.os, "killpg") as kill:
            result = permuter.check_one("unused", "fixture.c", 0x100000, "flags", None)
        self.assertEqual(result["err"], "TIMEOUT")
        self.assertEqual(process.communicate.call_count, 2)
        kill.assert_called_once()

    def test_failed_refresh_cannot_reuse_stale_candidates(self):
        with patch.object(worklist, "run_checked", return_value=None):
            with self.assertRaises(SystemExit):
                worklist.candidates()

    def test_worklist_reads_new_match_before_old_attempted_status(self):
        state = {"registered": [], "attempted": {"00100000": {"status": "BUDGET"}}}
        refined = {"best": {"match": True}, "origin": "fixture", "used": 4}
        with patch.object(worklist, "load_state", return_value=state), patch.object(
                worklist, "load_status", return_value={}), patch.object(
                worklist, "candidates", return_value=[(0x100000, 4)]), patch.object(
                worklist, "refine_state", return_value=refined), patch.object(
                worklist, "save_state"), contextlib.redirect_stdout(io.StringIO()) as output:
            worklist.next_candidate(10, None, as_json=True)
        self.assertEqual(json.loads(output.getvalue())["chosen"]["outcome"], "MATCH-unregistered")


if __name__ == "__main__":
    unittest.main()
