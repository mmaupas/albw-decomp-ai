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
import proposals_repair
import refine

RICH = """typedef unsigned int u32;
typedef unsigned char u8;
struct S { u32 f; u8 b; };
u32 helper(u32);
u32 func_00100000(struct S* self, u32 a, u32 b) {
    u32 x = a + b;
    u32 y = 0;
    if (a == b) {
        x = 0x10;
        y = x;
    } else {
        x = 0x20;
    }
    if (y != 0) {
        u32 z = y * 2;
        *(u8*)((char*)self + 0x2) = z;
    }
    *(u32*)((char*)self + 0x4) = x;
    return x;
}
"""

SPLIT = """typedef unsigned int u32;
u32 func_1(u32 a) {
    u32 x;
    x = a;
    x = x + 1;
    return x;
}
"""

LOOP = """typedef unsigned int u32;
u32 func_4(u32 a) {
    u32 x = 0;
    for (u32 i = 0; i < a; i++) { x = x + i; }
    x = x + 1;
    return x;
}
"""

PARAM_SWAP = """typedef unsigned int u32;
u32 func_5(u32 a, u32 b) { return a + b; }
"""

ASSIGN_GUARD = """typedef unsigned int u32;
u32 h(void);
u32 func_7(u32 a) {
    u32 x = 0;
    if ((x = h())) { x = 1; } else { x = 2; }
    return x;
}
"""

VOLATILE = """typedef unsigned char u8;
void func_8(u8* p) {
    volatile u8 *q = p;
    *q = 1;
    *q = *q + 1;
}
"""

IMPURE = """typedef unsigned int u32;
u32 g(u32);
u32 func_6(u32 a, u32 b) {
    u32 y = g(a) + b;
    u32 x = a * b;
    return x + y;
}
"""

ZERO_TEST = """typedef unsigned int u32;
u32 func_z(u32 a) {
    if (a == 0) { return 1; }
    return 0;
}
"""

DIFF = {"n_op": 2, "n_reg": 0, "perm": False, "words": 30, "total": 32,
        "diff_words": [{"offset": "0x1c", "target": "mov r3, #0x2a",
                        "mine": "mov r3, #0x10"}]}

FLAGS = "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections"
FLAGS_O2 = "--cpu=MPCore --fpmode=fast --apcs=/interwork -O2 -Otime --split_sections"


class ProposeTests(unittest.TestCase):
    def propose(self, src, **kw):
        kw.setdefault("name", "func_00100000" if "func_00100000" in src else None)
        return proposals_repair.propose(src, budget=100, **kw)

    def test_deterministic_and_ordered(self):
        a = self.propose(RICH, diff=DIFF, flags=FLAGS)
        b = self.propose(RICH, diff=DIFF, flags=FLAGS)
        self.assertEqual(a, b)
        self.assertEqual([v["index"] for v in a], list(range(1, len(a) + 1)))

    def test_variant_shape_full_source_unique_reason(self):
        vs = self.propose(RICH)
        self.assertTrue(vs)
        for v in vs:
            self.assertEqual(set(("index", "name", "family", "reason", "hash", "source")),
                             set(v))
            self.assertIn("func_00100000", v["source"])  # full source, not a fragment
            self.assertNotEqual(v["source"], RICH)
            self.assertTrue(v["reason"].strip())
            self.assertIn(v["family"], proposals_repair.FAMILY_ORDER)
        self.assertEqual(len({v["source"] for v in vs}), len(vs))
        self.assertEqual(len({v["hash"] for v in vs}), len(vs))

    def test_diff_driven_literal_is_variant_one(self):
        vs = self.propose(RICH, diff=DIFF, flags=FLAGS)
        self.assertEqual(vs[0]["family"], "literal_value")
        self.assertIn("0x2a", vs[0]["source"])
        self.assertIn("diff word", vs[0]["reason"])

    def test_without_diff_branch_arm_is_variant_one(self):
        vs = self.propose(RICH, flags=FLAGS)
        self.assertEqual(vs[0]["family"], "branch_arm")

    def test_budget_enforced(self):
        self.assertEqual(len(proposals_repair.propose(RICH, name="func_00100000",
                                                       budget=3)), 3)
        self.assertEqual(len(proposals_repair.propose(RICH, name="func_00100000",
                                                       budget=1)), 1)
        self.assertGreater(len(self.propose(RICH)), 3)

    def test_o2_flags_promote_register_lifetime(self):
        vs = self.propose(RICH, flags=FLAGS_O2)
        self.assertIn(vs[0]["family"], ("arg_register", "lifetime"))

    def test_branch_arm_swaps_arms_and_negates_guard(self):
        vs = [v for v in self.propose(RICH) if v["family"] == "branch_arm"]
        self.assertTrue(vs)
        swapped = [v for v in vs if "!(" in v["source"]]
        flipped = [v for v in vs if "a != b" in v["source"]]
        self.assertTrue(swapped and flipped)
        for v in swapped + flipped:
            # else arm comes first in the rewritten guard: 0x20 before 0x10
            self.assertLess(v["source"].index("0x20"), v["source"].index("0x10"))

    def test_branch_arm_skips_side_effect_guard(self):
        vs = self.propose(ASSIGN_GUARD)
        self.assertFalse([v for v in vs if v["family"] == "branch_arm"])

    def test_operand_commute_only_for_pure_commutative(self):
        vs = [v for v in self.propose(IMPURE, name="func_6") if v["family"] == "operand_order"]
        texts = [v["source"] for v in vs]
        self.assertTrue(any("a * b" not in t and "b * a" in t for t in texts))
        self.assertFalse(any("b + g(a)" in t for t in texts))  # impure RHS untouched

    def test_lifetime_split_introduces_used_fresh_local(self):
        vs = [v for v in self.propose(SPLIT, name="func_1") if "split" in v["reason"]]
        self.assertTrue(vs)
        src = vs[0]["source"]
        self.assertIn("x__r1", src)
        self.assertGreaterEqual(src.count("x__r1"), 2)  # declared AND used: no dummy
        self.assertIn("x__r1 = x + 1;", src)
        self.assertIn("return x__r1;", src)

    def test_lifetime_split_skipped_inside_loop(self):
        vs = self.propose(LOOP, name="func_4")
        self.assertFalse([v for v in vs if "split" in v["reason"]])

    def test_param_reorder_is_alpha_rename(self):
        vs = [v for v in self.propose(PARAM_SWAP, name="func_5")
              if "param reorder" in v["reason"]]
        self.assertTrue(vs)
        src = vs[0]["source"]
        self.assertIn("u32 func_5(u32 b,u32 a)", src)  # params swapped
        self.assertIn("return b + a;", src)           # uses swapped: semantics kept

    def test_param_signedness_nudge_only_for_zero_tests(self):
        vs = self.propose(ZERO_TEST, name="func_z")
        nudges = [v for v in vs if "signedness" in v["reason"]]
        self.assertTrue(nudges)
        vs2 = self.propose(PARAM_SWAP, name="func_5")
        self.assertFalse([v for v in vs2 if "signedness" in v["reason"]])

    def test_bool_cast_inserted_on_guards(self):
        vs = [v for v in self.propose(RICH) if v["family"] == "bool_cast"]
        self.assertTrue(vs)
        self.assertTrue(any("(s32)(a == b)" in v["source"] for v in vs))

    def test_volatile_move_only_when_present(self):
        vs = self.propose(VOLATILE, name="func_8")
        moved = [v for v in vs if v["family"] == "volatile_move"]
        self.assertTrue(moved)
        self.assertIn("*(volatile u8 *)q", moved[0]["source"])
        self.assertNotIn("volatile u8 *q", moved[0]["source"])
        self.assertFalse([v for v in self.propose(RICH) if v["family"] == "volatile_move"])

    def test_skip_hashes_excludes_rejected(self):
        all_vs = self.propose(RICH)
        target = all_vs[0]["hash"]
        rep = proposals_repair.run_pass(RICH, name="func_00100000", budget=100,
                                        skip_hashes={target})
        self.assertNotIn(target, [v["hash"] for v in rep["variants"]])
        self.assertGreaterEqual(rep["skipped"], 1)

    def test_load_rejected_hashes_reads_permuter_cache_read_only(self):
        with tempfile.TemporaryDirectory() as root:
            cache = Path(root) / "logs" / "permuter" / "00100000" / "tried.txt"
            cache.parent.mkdir(parents=True)
            cache.write_text("deadbeefdeadbeef\n")
            rej = proposals_repair.load_rejected_hashes(root, 0x100000)
            self.assertEqual(rej, {"deadbeefdeadbeef"})
            self.assertEqual(cache.read_text(), "deadbeefdeadbeef\n")  # untouched


class RefineRepairWiringTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "functions.json").write_text("{}")
        self.source = self.root / "source.cpp"
        self.source.write_text(RICH)
        self.visited = []
        for patcher in (
                patch.object(refine, "ROOT", str(self.root)),
                patch.object(refine, "gen_order", return_value=[]),
                patch.object(refine, "check_one", side_effect=self.fake_check),
                patch.object(refine, "classify", side_effect=lambda *a: dict(
                    n_op=2, n_reg=0, perm=False))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def fake_check(self, directory, source, addr, flags, sym, **kwargs):
        self.visited.append(Path(source).read_text())
        return dict(match=False, err="", words=1, total=2, sim=50.0, out="fixture")

    def run_refine(self, budget, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = refine.run(0x100000, budget=budget, src=str(self.source),
                                as_json=True, **kwargs)
        return result, output.getvalue()

    def state(self):
        return json.loads((self.root / "logs/refine/00100000/state.json").read_text())

    def test_repair_wave_records_proposals_and_state(self):
        result, out = self.run_refine(10, proposals="repair", repair_budget=4)
        st = self.state()
        self.assertIn("repair", st)
        self.assertGreaterEqual(st["repair"]["proposed"], 1)
        self.assertEqual(st["repair"]["budget"], 4)
        self.assertIn("repair", st["tried"])
        self.assertTrue(st["proposals"])
        for p in st["proposals"]:
            self.assertEqual(set(("name", "family", "reason", "hash", "wave", "match")),
                             set(p))
            self.assertEqual(p["wave"], "repair")
            self.assertTrue(p["reason"])
        self.assertTrue(st["rejected_hashes"])  # non-matches recorded, not re-proposed
        doc = json.loads(out)
        self.assertIn("repair", doc)
        self.assertEqual(doc["repair"]["budget"], 4)
        self.assertTrue(doc["repair"]["proposals"])
        # repair variants were actually checked (written into waves/)
        waves = list((self.root / "logs/refine/00100000/waves").glob("v*_*.cpp"))
        self.assertGreaterEqual(len(waves), 2)

    def test_default_run_has_no_repair_keys(self):
        result, out = self.run_refine(10)
        st = self.state()
        for key in ("repair", "proposals", "rejected_hashes"):
            self.assertNotIn(key, st)
        self.assertNotIn("repair", json.loads(out))
        self.assertNotIn("repair", result)
        self.assertEqual(len(self.visited), 1 + 3)  # baseline + flags wave only

    def test_unknown_proposal_source_rejected(self):
        with self.assertRaises(ValueError):
            self.run_refine(10, proposals="bogus")

    def test_resume_does_not_recheck_repair_variants(self):
        self.run_refine(10, proposals="repair", repair_budget=4)
        first = [p["hash"] for p in self.state()["proposals"]]
        self.visited.clear()
        self.run_refine(12, proposals="repair", repair_budget=4)
        st = self.state()
        self.assertEqual([p["hash"] for p in st["proposals"]], first)  # no re-proposal
        self.assertTrue(all(h in st["rejected_hashes"] for h in first))

    def test_propose_batch_offline_json_schema(self):
        sd = self.root / "logs/refine/00100000"
        sd.mkdir(parents=True)
        (sd / "best.cpp").write_text(RICH)
        (sd / "state.json").write_text(json.dumps({
            "addr": "00100000", "used": 5, "origin": "twin:x", "name": "func_00100000",
            "flags_base": FLAGS, "tried": ["repair"],
            "best": {"path": str(sd / "best.cpp"), "n_op": 2, "n_reg": 0,
                     "perm": False, "words": 30, "total": 32, "sim": 90.0,
                     "match": False, "flags": FLAGS, "err": ""}}))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            targets = refine.propose_batch([0x100000], repair_budget=6, as_json=True)
        doc = json.loads(out.getvalue())
        self.assertEqual(len(doc["targets"]), 1)
        t = doc["targets"][0]
        self.assertEqual(t["addr"], "00100000")
        self.assertEqual(t["budget"], 6)
        self.assertLessEqual(len(t["proposed"]), 6)
        for p in t["proposed"]:
            self.assertEqual(set(("index", "name", "family", "reason", "hash")), set(p))
        self.assertIn("skipped", t)
        self.assertIn("families", t)
        self.assertIn("seconds", t)
        self.assertEqual(targets, doc["targets"])
        # no addr argument: near-misses are discovered from logs/refine
        with contextlib.redirect_stdout(io.StringIO()):
            auto = refine.propose_batch([], repair_budget=6)
        self.assertEqual([t["addr"] for t in auto], ["00100000"])

    def test_propose_batch_skips_rejected_hashes(self):
        sd = self.root / "logs/refine/00100000"
        sd.mkdir(parents=True)
        (sd / "best.cpp").write_text(RICH)
        (sd / "state.json").write_text(json.dumps({
            "best": {"path": str(sd / "best.cpp"), "n_op": 2, "match": False}}))
        first = refine.propose_batch([0x100000], repair_budget=6)[0]
        victim = first["proposed"][0]["hash"]
        st = json.loads((sd / "state.json").read_text())
        st["rejected_hashes"] = [victim]
        (sd / "state.json").write_text(json.dumps(st))
        with contextlib.redirect_stdout(io.StringIO()):
            second = refine.propose_batch([0x100000], repair_budget=6)[0]
        self.assertNotIn(victim, [p["hash"] for p in second["proposed"]])
        self.assertGreaterEqual(second["skipped"], 1)

    def test_propose_batch_reports_missing_near_miss(self):
        with contextlib.redirect_stdout(io.StringIO()):
            targets = refine.propose_batch([0x200000], as_json=True)
        self.assertIn("error", targets[0])


if __name__ == "__main__":
    unittest.main()
