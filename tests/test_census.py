import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import audit
import census

needs_capstone = unittest.skipIf(census.Cs is None,
                                 "capstone not installed (uv sync); stdlib-only runs skip this")

TEXT_START = 0x100000
TEXT_SIZE = 0x1000


def synth_fixture():
    """Synthetic ledger: 8 functions over 0x100000..0x101000 (TEXT_SIZE=0x1000).

    00100000 honest 16B, 00100010 hack 16B          -> matched (not census)
    00100020 lifted 32B                              -> pool lifted
    00100040 excluded_library 16B                    -> pool excluded_library
    00100050 no_source label=source_lost 16B         -> pool source_lost
    00100060 unmatched, instr svc+recipe             -> svc_region (precedence over parked)
    00100080 unmatched, instr recipe only            -> parked_recipe
    00100090 unmatched, instr recipe+fam             -> parked_recipe (precedence over shape)
    001000A0 unmatched, instr fam + sead symbol      -> shape_family_residue (precedence over sead)
    001000C0 unmatched, sead symbol + hot            -> sead_named (precedence over hot)
    001000E0 unmatched, hot size only, 0x800B        -> hot_bespoke
    00100900 unmatched, plain                        -> other
    """
    functions = {
        "00100000": {"status": "honest", "path": "src/x.c", "cc": "4.1/b1049", "hack_reasons": []},
        "00100010": {"status": "hack", "path": "src/y.c", "cc": "4.1/b1049", "hack_reasons": ["weak"]},
        "00100020": {"status": "lifted", "path": "src_lifted/func_00100020.c", "cc": "4.1/b1049"},
        "00100040": {"status": "excluded_library"},
        "00100050": {"status": "no_source", "label": "source_lost", "note": "lost"},
        "00100060": {},
        "00100080": {},
        "001000A0": {},
        "001000C0": {},
        "001000E0": {},
        "00100900": {},
    }
    starts = [0x100000, 0x100010, 0x100020, 0x100040, 0x100050, 0x100060,
              0x100080, 0x1000A0, 0x1000C0, 0x1000E0, 0x100900]
    sizes = {0x100000: 0x10, 0x100010: 0x10, 0x100020: 0x20, 0x100040: 0x10,
             0x100050: 0x10, 0x100060: 0x20, 0x100080: 0x20, 0x1000A0: 0x20,
             0x1000C0: 0x20, 0x1000E0: 0x820, 0x100900: 0x700}
    symbols = {0x1000A0: "sead::Thing::do()", 0x1000C0: "nn::fs::Load()"}
    instr = {
        0x100060: {"motifs": ["m1"], "recipe": "neg-svc-stub", "has_svc": True, "svc": [0x17],
                    "has_vfp": False, "has_ldrex_strex": False, "has_ldm_stm": False},
        0x100080: {"motifs": ["m2"], "recipe": "neg-fam-sti-third-pool-word", "has_svc": False, "svc": [],
                    "has_vfp": False, "has_ldrex_strex": False, "has_ldm_stm": False},
        0x1000A0: {"motifs": ["m3"], "recipe": None, "has_svc": False, "svc": [],
                    "has_vfp": False, "has_ldrex_strex": False, "has_ldm_stm": False},
    }
    fam_of = {0x1000A0: ["Id64"]}
    hot = {0x1000C0: {"coverage_rank": 7, "hits": 99}, 0x1000E0: {"size_rank": 1, "size": 0x820}}
    return functions, starts, sizes, symbols, instr, fam_of, hot


_UNSET = object()


def build(instr=_UNSET, fam_of=_UNSET, hot=_UNSET, symbols=_UNSET, text_size=TEXT_SIZE):
    functions, starts, sizes, symbols0, instr0, fam_of0, hot0 = synth_fixture()
    real_sizes = census.function_sizes(starts, TEXT_START, text_size)
    assert real_sizes == sizes, (real_sizes, sizes)
    if instr is _UNSET:
        instr = instr0
    if fam_of is _UNSET:
        fam_of = fam_of0
    if hot is _UNSET:
        hot = hot0
    if symbols is _UNSET:
        symbols = symbols0
    return census.build_census(
        functions, starts, symbols=symbols, instr=instr, fam_of=fam_of, hot=hot,
        mode="full" if instr is not None else "offline",
        text_start=TEXT_START, text_size=text_size)


class SizeSourceTests(unittest.TestCase):
    def test_sizes_use_audit_convention(self):
        starts = [0x100000, 0x100010, 0x100030]
        sizes = census.function_sizes(starts, TEXT_START, 0x100)
        self.assertEqual(sizes, {0x100000: 0x10, 0x100010: 0x20, 0x100030: 0xD0})
        repo_starts = audit.read_json(os.path.join(census.ROOT, "funcs.json"))["starts"]
        repo_sizes = census.function_sizes(repo_starts)
        self.assertEqual(sum(repo_sizes.values()), 5841180)
        self.assertEqual(repo_sizes[repo_starts[-1]],
                         0x100000 + 5841180 - repo_starts[-1])


class PrecedenceTests(unittest.TestCase):
    def test_every_function_classified_exactly_once_and_pools_reconcile(self):
        c = build()
        self.assertEqual(len(c["functions"]), 9)
        pools = {a: e["pool"] for a, e in c["functions"].items()}
        self.assertEqual(pools["00100020"], "lifted")
        self.assertEqual(pools["00100040"], "excluded_library")
        self.assertEqual(pools["00100050"], "source_lost")
        self.assertEqual(pools["00100060"], "svc_region")
        self.assertEqual(pools["00100080"], "parked_recipe")
        self.assertEqual(pools["001000A0"], "shape_family_residue")
        self.assertEqual(pools["001000C0"], "sead_named")
        self.assertEqual(pools["001000E0"], "hot_bespoke")
        self.assertEqual(pools["00100900"], "other")
        rec = c["reconciliation"]
        self.assertTrue(rec["every_function_classified_once"])
        self.assertTrue(rec["pools_sum_equals_census"])
        self.assertEqual(rec["sum_of_pool_bytes"], 0x20 + 0x10 + 0x10 + 0x20 + 0x20 + 0x20 + 0x20 + 0x820 + 0x700)

    def test_ledger_pools_beat_instruction_pools(self):
        functions, starts, _s, symbols, instr, fam_of, hot = synth_fixture()
        instr[0x100020] = dict(instr[0x100060])  # lifted function also carries svc
        c = census.build_census(functions, starts, symbols=symbols, instr=instr,
                                fam_of=fam_of, hot=hot, mode="full",
                                text_start=TEXT_START, text_size=TEXT_SIZE)
        self.assertEqual(c["functions"]["00100020"]["pool"], "lifted")

    def test_svc_beats_parked_beats_shape_beats_sead_beats_hot(self):
        self.assertEqual(census.classify(0x1, 4, {}, "unmatched",
                                         {0x1: {"has_svc": True, "svc": [1], "recipe": "neg-svc-stub"}},
                                         {}, {}, {})[0], "svc_region")
        self.assertEqual(census.classify(0x1, 4, {}, "unmatched",
                                         {0x1: {"has_svc": False, "svc": [], "recipe": "neg-x"}},
                                         {0x1: ["Id64"]}, {0x1: {"symbol": "sead::x"}}, {0x1: {}})[0],
                         "parked_recipe")
        self.assertEqual(census.classify(0x1, 4, {}, "unmatched",
                                         {0x1: {"has_svc": False, "svc": [], "recipe": None}},
                                         {0x1: ["Id64"]}, {0x1: {"symbol": "sead::x"}}, {0x1: {}})[0],
                         "shape_family_residue")
        self.assertEqual(census.classify(0x1, 4, {}, "unmatched", None,
                                         {}, {0x1: {"symbol": "nn::x"}}, {0x1: {}})[0], "sead_named")
        self.assertEqual(census.classify(0x1, 4, {}, "unmatched", None,
                                         {}, {}, {0x1: {"size_rank": 3}})[0], "hot_bespoke")
        self.assertEqual(census.classify(0x1, 4, {}, "unmatched", None, {}, {}, {})[0], "other")

    def test_source_lost_matches_no_source_and_label(self):
        pool, ev = census.classify(0x1, 4, {"label": "source_lost"}, "no_source", None, {}, {}, {})
        self.assertEqual((pool, ev["label"]), ("source_lost", "source_lost"))
        pool, _ = census.classify(0x1, 4, {"label": "other"}, "no_source", None, {}, {}, {})
        self.assertEqual(pool, "source_lost")

    def test_offline_mode_degrades_instruction_pools_to_null(self):
        c = build(instr=None, fam_of=None, hot={0x1000E0: {"size_rank": 1, "size": 0x820}},
                  symbols={})
        self.assertEqual(c["mode"], "offline")
        for p in census.INSTRUCTION_POOLS:
            self.assertFalse(c["pools"][p]["available"])
            self.assertIsNone(c["pools"][p]["bytes"])
            self.assertIsNone(c["pools"][p]["functions"])
        self.assertIsNone(c["instruction_metadata"])
        self.assertIn("setup_hint", c)
        self.assertEqual(c["pools"]["svc_region"]["bytes"], None)
        self.assertIsNone(c["exclusion"]["share_vs_target_minus_svc_and_library"])
        self.assertIn("00100060", c["functions"])
        self.assertNotEqual(c["functions"]["00100060"]["pool"], "svc_region")


class ArithmeticTests(unittest.TestCase):
    def test_gap_math_exact(self):
        c = build()
        g = c["gap"]
        self.assertEqual(g["honest_bytes_now"], 0x10)
        self.assertEqual(g["goal_honest_bytes"], TEXT_SIZE // 2)
        self.assertEqual(g["needed_honest_bytes"], TEXT_SIZE // 2 - 0x10)
        self.assertEqual(g["census_bytes"], TEXT_SIZE - 0x20)
        self.assertEqual(g["census_functions"], 9)

    def test_exclusion_shown_both_ways(self):
        c = build()
        ex = c["exclusion"]
        self.assertEqual(ex["excluded_library_bytes"], 0x10)
        self.assertAlmostEqual(ex["share_vs_full_text"]["share_pct"], 100.0 * 0x10 / TEXT_SIZE, places=3)
        self.assertAlmostEqual(ex["share_vs_target_minus_excluded_library"]["share_pct"],
                               100.0 * 0x10 / (TEXT_SIZE - 0x10), places=3)
        self.assertEqual(ex["share_vs_target_minus_svc_and_library"]["target_bytes"],
                         TEXT_SIZE - 0x10 - 0x20)

    def test_pool_detail_rankings(self):
        c = build()
        rec = c["pools"]["parked_recipe"]["detail"]["recipes_by_bytes"]
        self.assertEqual(set(rec), {"neg-fam-sti-third-pool-word"})
        self.assertEqual(rec["neg-fam-sti-third-pool-word"], {"functions": 1, "bytes": 0x20})
        svc = c["pools"]["svc_region"]["detail"]["svc_numbers"]
        self.assertEqual(svc["0x17"], {"functions": 1, "bytes": 0x20})
        fam = c["pools"]["shape_family_residue"]["detail"]["families_by_bytes"]
        self.assertEqual(fam["Id64"], {"functions": 1, "bytes": 0x20})

    def test_instruction_metadata_recorded(self):
        c = build()
        im = c["instruction_metadata"]
        self.assertTrue(im["available"])
        self.assertEqual(im["has_svc"]["functions"], 1)
        self.assertEqual(im["has_svc"]["bytes"], 0x20)

    def test_determinism_identical_output(self):
        a = census.canonical_json(build())
        b = census.canonical_json(build())
        self.assertEqual(a, b)


class HelperTests(unittest.TestCase):
    def test_sead_named_map_start_and_interior_symbols(self):
        items = [(0x100000, 0x100, {}, "unmatched"), (0x100200, 0x100, {}, "unmatched")]
        symbols = {0x100000: "plain name", 0x100010: "sead::ListNode::erase_()",
                   0x100250: "nn::math::MTX34 inverse"}
        out = census.sead_named_map(items, symbols)
        self.assertEqual(set(out), {0x100000, 0x100200})
        self.assertEqual(out[0x100000]["symbol"], "sead::ListNode::erase_()")
        self.assertEqual(out[0x100200]["symbol_addr"], "00100250")

    def test_hot_size_map_threshold_and_top(self):
        items = [(0x100000 + 0x10 * i, 0x800 if i == 0 else (0x500 if i < 4 else 0x10), {}, "unmatched")
                 for i in range(10)]
        out = census.hot_size_map(items)
        self.assertEqual(set(out), {0x100000, 0x100010, 0x100020, 0x100030})
        self.assertEqual(out[0x100000]["size_rank"], 1)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        return subprocess.run([sys.executable, os.path.join(census.ROOT, "tools", "census.py"), *argv],
                              capture_output=True, text=True, cwd=census.ROOT)

    def test_json_degrades_exit2_without_code_bin(self):
        proc = self.run_cli("--json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("code.bin", proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["mode"], "offline")
        for p in census.INSTRUCTION_POOLS:
            self.assertFalse(data["pools"][p]["available"])
        rec = data["reconciliation"]
        self.assertTrue(rec["pools_sum_equals_census"] and rec["every_function_classified_once"])
        self.assertTrue(rec["audit_stats_match"])
        stats = audit.stats(audit.load())
        self.assertEqual(data["totals"]["bytes_by_status"], stats["bytes_by_status"])
        self.assertEqual(data["totals"]["census_bytes"],
                         5841180 - stats["bytes_by_status"]["honest"] - stats["bytes_by_status"]["hack"])
        self.assertEqual(data["gap"]["needed_honest_bytes"], 5841180 // 2 - 1303428)

    def test_json_is_deterministic(self):
        a = self.run_cli("--json")
        b = self.run_cli("--json")
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(a.returncode, b.returncode)

    def test_pools_and_functions_subcommands(self):
        pools = json.loads(self.run_cli("pools", "--json").stdout)
        self.assertIn("pools", pools)
        self.assertEqual(set(pools["pools"]), set(census.POOLS))
        stats = audit.stats(audit.load())
        funcs = json.loads(self.run_cli("functions", "--json").stdout)
        self.assertEqual(len(funcs), stats["total_functions"] - stats["matched_source_included"])
        lifted = json.loads(self.run_cli("functions", "--pool", "lifted", "--json").stdout)
        self.assertEqual(len(lifted), stats["lifted"])
        self.assertTrue(all(r["pool"] == "lifted" for r in lifted))
        self.assertEqual(sum(r["size"] for r in lifted), stats["bytes_by_status"]["lifted"])

    def test_write_then_check_roundtrip_in_tempdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            cj = os.path.join(tmp, "census.json")
            md = os.path.join(tmp, "census.md")
            with open(md, "w", encoding="utf-8") as fh:
                fh.write("# doc\n\n" + census.DOC_BEGIN + "\nplaceholder\n" + census.DOC_END + "\n")
            synthetic = build()
            with patch.object(census, "CENSUS_JSON", cj), patch.object(census, "CENSUS_MD", md), \
                    patch.object(census, "build_canonical", lambda: synthetic), \
                    patch.object(census, "FULL_DIR", os.path.join(tmp, "logs")):
                self.assertEqual(census.cmd_write(write_full=False), 0)
                self.assertEqual(census.cmd_check(), 0)
                with open(cj, encoding="utf-8") as fh:
                    self.assertEqual(json.loads(fh.read())["gap"]["needed_honest_bytes"],
                                     TEXT_SIZE // 2 - 0x10)
                with open(md, encoding="utf-8") as fh:
                    self.assertIn(census.DOC_BEGIN, fh.read())
                with open(cj, "a", encoding="utf-8") as fh:
                    fh.write(" ")
                self.assertEqual(census.cmd_check(), 1)

    def test_doc_render_contains_three_answers(self):
        text = census.render_doc(build())
        self.assertIn("Answer 1", text)
        self.assertIn("Answer 2", text)
        self.assertIn("Answer 3", text)
        self.assertIn("neg-fam-sti-third-pool-word", text)
        self.assertIn("both ways", text)


@needs_capstone
class CapstonePassTests(unittest.TestCase):
    def test_scan_instructions_records_svc_and_recipe(self):
        import fn
        image = bytearray(0x40)
        words = [0xEF000017, 0xE12FFF1E, 0xE1A00000, 0xE12FFF1E,
                 0xE8910003, 0xE12FFF1E, 0xE1A00000, 0xE12FFF1E]
        for i, w in enumerate(words):
            image[i * 4:i * 4 + 4] = w.to_bytes(4, "little")
        with patch.object(fn, "STARTS", [0x100000, 0x100010, 0x100020]), \
                patch.object(fn, "TEXT_END", 0x100020), patch.object(fn, "CODE", bytes(image)):
            out = census.scan_instructions(bytes(image), [0x100000, 0x100010])
        self.assertTrue(out[0x100000]["has_svc"])
        self.assertEqual(out[0x100000]["svc"], [0x17])
        self.assertEqual(out[0x100000]["recipe"], "neg-svc-stub")
        self.assertFalse(out[0x100010]["has_svc"])
        self.assertIsNone(out[0x100010]["recipe"])
        self.assertTrue(out[0x100010]["has_ldm_stm"])


if __name__ == "__main__":
    unittest.main()
