import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import migrate_src_paths as mig


def make_root():
    """Synthetic repo root: campaign tree + auto batch + sead file + lifted.

    00100000 honest  src/work7/ds7/func_00100000.c            -> game
    00100010 honest  src/work8/auto/func_00100010.cpp         -> twins (cross-include)
    00100020 honest  src/work5/agent1/func_00100020.cpp       -> sead (symbol in range; same-dir include)
    00100030 lifted  src_lifted/func_00100030.c               -> lifted mirror
    00100040 unmatched (no path)
    helpers: src/work7/ds7/range.h, src/work5/agent1/helper.h (unregistered)
    """
    tmp = tempfile.TemporaryDirectory()
    root = tmp.name
    os.makedirs(os.path.join(root, "shared"))
    starts = [0x100000 + 0x10 * i for i in range(5)]
    functions = {
        "00100000": {"status": "honest", "path": "src/work7/ds7/func_00100000.c",
                     "cc": "4.1/b1049", "hack_reasons": []},
        "00100010": {"status": "honest", "path": "src/work8/auto/func_00100010.cpp",
                     "cc": "4.1/b1049", "hack_reasons": []},
        "00100020": {"status": "honest", "path": "src/work5/agent1/func_00100020.cpp",
                     "cc": "4.1/b1049", "hack_reasons": []},
        "00100030": {"status": "lifted", "path": "src_lifted/func_00100030.c",
                     "cc": "4.1/b1049"},
        "00100040": {},
    }
    contents = {
        "src/work7/ds7/func_00100000.c": "u32 f0(u32 r0) { return r0; }\n",
        "src/work7/ds7/range.h": "#define RANGE 1\n",
        "src/work8/auto/func_00100010.cpp": '#include "../../work7/ds7/range.h"\nu32 f1(u32 r0) { return r0 + RANGE; }\n',
        "src/work5/agent1/func_00100020.cpp": '#include "helper.h"\nu32 f2(u32 r0) { return r0 + H; }\n',
        "src/work5/agent1/helper.h": "#define H 2\n",
        "src_lifted/func_00100030.c": "/* LIFTED */\nu32 func_00100030(u32 r0) { return r0; }\n",
    }
    for p, text in contents.items():
        full = os.path.join(root, p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(text)
    with open(os.path.join(root, "functions.json"), "w") as fh:
        json.dump(functions, fh, indent=1, sort_keys=True)
    with open(os.path.join(root, "funcs.json"), "w") as fh:
        json.dump({"starts": starts}, fh)
    with open(os.path.join(root, "shared", "symbols.jsonl"), "w") as fh:
        fh.write(json.dumps({"addr": "00100020", "name": "sead::ListNode::erase_()"}) + "\n")
    with open(os.path.join(root, "shared", "shape_verification.json"), "w") as fh:
        json.dump({"shapes": {"albw::X": {"sites": [
            {"addr": "00100000", "path": "src/work7/ds7/func_00100000.c",
             "status": "honest", "check": "MATCH", "tricks": [], "header": False}]}}}, fh)
    return tmp, root, functions, contents


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.root, self.functions, self.contents = make_root()
        self.addCleanup(self.tmp.cleanup)

    def test_classification_whole_tree(self):
        _data, mapping, classes = mig.build_mapping(self.root)
        self.assertEqual(mapping["src/work7/ds7/func_00100000.c"], "src/game/ds7/func_00100000.c")
        self.assertEqual(mapping["src/work7/ds7/range.h"], "src/game/ds7/range.h")
        self.assertEqual(mapping["src/work8/auto/func_00100010.cpp"], "src/twins/func_00100010.cpp")
        self.assertEqual(mapping["src/work5/agent1/func_00100020.cpp"], "src/sead/agent1/func_00100020.cpp")
        self.assertEqual(mapping["src/work5/agent1/helper.h"], "src/game/agent1/helper.h")
        self.assertEqual(mapping["src_lifted/func_00100030.c"], "src_lifted/game/func_00100030.c")
        self.assertEqual(len(set(mapping.values())), len(mapping))

    def test_apply_moves_rebases_and_rewrites_ledger(self):
        mig.apply_migration(self.root, regen=False)
        data = mig.read_json(os.path.join(self.root, "functions.json"))
        self.assertEqual(data["00100000"]["path"], "src/game/ds7/func_00100000.c")
        self.assertEqual(data["00100010"]["path"], "src/twins/func_00100010.cpp")
        self.assertEqual(data["00100020"]["path"], "src/sead/agent1/func_00100020.cpp")
        self.assertEqual(data["00100030"]["path"], "src_lifted/game/func_00100030.c")
        self.assertEqual(data["00100030"]["status"], "lifted")
        self.assertEqual(data["00100040"], {})
        # canonical format preserved
        with open(os.path.join(self.root, "functions.json")) as fh:
            self.assertEqual(fh.read(), mig.audit.canonical_bytes(data))
        # old locations gone, new locations present
        self.assertFalse(os.path.exists(os.path.join(self.root, "src/work7")))
        # untouched file keeps its bytes
        with open(os.path.join(self.root, "src/game/ds7/func_00100000.c")) as fh:
            self.assertEqual(fh.read(), self.contents["src/work7/ds7/func_00100000.c"])
        # includes rebased to the target's new home
        with open(os.path.join(self.root, "src/twins/func_00100010.cpp")) as fh:
            self.assertIn('#include "../game/ds7/range.h"', fh.read())
        with open(os.path.join(self.root, "src/sead/agent1/func_00100020.cpp")) as fh:
            self.assertIn('#include "../../game/agent1/helper.h"', fh.read())
        # helper moved with its subtree
        with open(os.path.join(self.root, "src/game/ds7/range.h")) as fh:
            self.assertEqual(fh.read(), "#define RANGE 1\n")

    def test_shape_sites_rewritten_checks_preserved(self):
        mig.apply_migration(self.root, regen=False)
        report = mig.read_json(os.path.join(self.root, "shared", "shape_verification.json"))
        site = report["shapes"]["albw::X"]["sites"][0]
        self.assertEqual(site["path"], "src/game/ds7/func_00100000.c")
        self.assertEqual(site["check"], "MATCH")

    def test_idempotent_second_run(self):
        mig.apply_migration(self.root, regen=False)
        _data, mapping2, classes2 = mig.build_mapping(self.root)
        self.assertTrue(all(c == "done" for c in classes2.values()))
        self.assertTrue(all(old == new for old, new in mapping2.items()))

    def test_check_mode(self):
        self.assertEqual(mig.check(self.root), 1)  # not migrated yet
        mig.apply_migration(self.root, regen=False)
        self.assertEqual(mig.check(self.root), 0)


if __name__ == "__main__":
    unittest.main()
