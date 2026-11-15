import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import reharvest


class ResolveTargetsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        sm = self.root / "shapemine"
        sm.mkdir()
        (sm / "fn.jsonl").write_text("\n".join([
            json.dumps({"addr": "00000001", "motifs": ["aa", "bb"]}),
            json.dumps({"addr": "00000002", "motifs": ["aa", "bb", "cc"]}),
            json.dumps({"addr": "00000003", "motifs": ["aa", "bb"]}),
            json.dumps({"addr": "00000009", "motifs": ["aa", "bb", "dd"]}),  # unindexed
            json.dumps({"addr": "0000000A", "motifs": ["bb", "dd"]}),        # unindexed
            json.dumps({"addr": "0000000B", "motifs": ["ee"]}),              # unrelated
        ]) + "\n")
        (sm / "motifs.json").write_text(json.dumps({"lines": 6, "motifs": {
            "aa": {"sig": "s-a", "m": ["00000001", "00000002", "00000003"], "u": ["00000009"]},
            "bb": {"sig": "s-b", "m": ["00000001", "00000002", "00000003"], "u": ["00000009", "0000000A"]},
            "cc": {"sig": "s-c", "m": ["00000002"], "u": []},
            "dd": {"sig": "s-d", "m": [], "u": ["00000009", "0000000A"]},
            "ee": {"sig": "s-e", "m": [], "u": ["0000000B"]},
        }}))
        (self.root / "functions.json").write_text(json.dumps({
            "00000001": {"status": "honest", "path": "src/a.cpp"},
            "00000002": {"status": "honest", "path": "src/b.cpp"},
            "00000003": {"status": "honest", "path": "src/c.cpp"},
        }))
        (self.root / "shape_verification.json").write_text(json.dumps({"shapes": {
            "albw::Id64": {"sites": [
                {"addr": "00000001", "check": "MATCH", "status": "honest", "tricks": []},
                {"addr": "00000002", "check": "MATCH", "status": "honest", "tricks": []},
                {"addr": "00000003", "check": "MATCH", "status": "honest", "tricks": []},
            ]},
        }}))
        for name, val in (("ROOT", str(self.root)), ("REPORT", str(self.root / "shape_verification.json")),
                          ("SHAPEMINE", str(sm))):
            patcher = patch.object(reharvest, name, val)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_signature_needs_three_sites(self):
        motifs = reharvest.fn_motifs()
        sig, sites = reharvest.shape_motif_signature("albw::Id64", motifs)
        self.assertEqual(sig, {"aa", "bb"})  # cc appears in only 1 site
        self.assertEqual(len(sites), 3)

    def test_targets_ranked_by_overlap_and_exclude_registered(self):
        ranked, sites = reharvest.resolve_targets("albw::Id64", top=10)
        # 00000009 hits aa+bb (2), 0000000A hits bb only (1); 0000000B unrelated
        self.assertEqual(ranked, [("00000009", 2), ("0000000A", 1)])

    def test_unknown_shape_yields_nothing(self):
        ranked, sites = reharvest.resolve_targets("albw::Nope", top=10)
        self.assertEqual(ranked, [])
        self.assertEqual(sites, [])


if __name__ == "__main__":
    unittest.main()
