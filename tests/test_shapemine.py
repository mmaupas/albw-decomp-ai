import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import shapemine


class TokenTests(unittest.TestCase):
    def test_condition_stripped_and_registers_collapse(self):
        self.assertEqual(shapemine.token_of("ldrne", "r3, [r0, #0x74]"),
                         "ldr r, [r, #]")
        self.assertEqual(shapemine.token_of("add", "r2, r2, r1, lsl #2"),
                         "add r, r, r, lsl #")
        self.assertEqual(shapemine.token_of("push", "{r4, r5, lr}"), "push {r, r, lr}")

    def test_pool_and_call_normalization(self):
        self.assertEqual(shapemine.token_of("ldr", "r0, [pc, #0x1c]"), "ldr r, POOL")
        self.assertEqual(shapemine.token_of("bl", "#0x12345"), "bl CALL")
        self.assertEqual(shapemine.token_of("bx", "lr"), "bx lr")

    def test_ngrams_dedupe_and_sizes(self):
        toks = ["a", "b", "c", "d", "e", "a", "b", "c", "d"]
        sigs = shapemine.ngrams(toks, ns=(4,))
        self.assertEqual(len(sigs), len(set(sigs)))
        self.assertIn("a ; b ; c ; d", sigs)
        # 9 tokens -> 6 4-gram positions, but "a ; b ; c ; d" occurs twice -> 5 unique
        self.assertEqual(len([s for s in sigs if s.count(" ; ") == 3]), 5)
        self.assertEqual(sigs, shapemine.ngrams(toks, ns=(4,)))

    def test_motif_id_stable(self):
        self.assertEqual(shapemine.motif_id("x ; y"), shapemine.motif_id("x ; y"))
        self.assertNotEqual(shapemine.motif_id("x ; y"), shapemine.motif_id("x ; z"))
        self.assertEqual(len(shapemine.motif_id("x")), 16)


class RankTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "functions.json").write_text(json.dumps({
            "00000001": {"status": "honest", "path": "src/a.cpp", "cc": "4.1/b1049"},
            "00000002": {"status": "honest", "path": "src/a.cpp", "cc": "4.1/b1049"},
            "00000003": {"status": "honest", "path": "src/b.cpp", "cc": "4.1/b1049"},
            "00000004": {"status": "no_source"},
            "00000005": {"status": "no_source"},
        }))
        patcher = patch.object(shapemine, "ROOT", str(self.root))
        patcher.start()
        self.addCleanup(patcher.stop)

    def motifs(self):
        return {
            "aaa": {"sig": "s1", "m": ["00000001", "00000002", "00000003"], "u": ["00000004", "00000005"]},
            "bbb": {"sig": "s2", "m": ["00000001"], "u": ["00000004", "00000005", "00000006"]},
            "ccc": {"sig": "s3", "m": ["00000001", "00000002", "00000003"], "u": []},
        }

    def test_rank_filters_and_scores(self):
        rows = shapemine.rank_clusters(self.motifs(), min_files=2, min_unlock=1, top=10)
        self.assertEqual([r["id"] for r in rows], ["aaa"])  # bbb has 1 file, ccc unlocks 0
        self.assertEqual(rows[0]["files"], 2)  # a.cpp shared by two functions counts once
        self.assertEqual(rows[0]["score"], 2 * 2)

    def test_rank_sort_variants(self):
        rows = shapemine.rank_clusters(self.motifs(), min_files=1, min_unlock=0, sort="unlock", top=10)
        self.assertEqual(rows[0]["id"], "bbb")

    def test_focus_stores_keeps_only_store_dense_call_free(self):
        motifs = {
            "s1": {"sig": "str r, [r, #] ; str r, [r, #] ; str r, [r, #] ; bx lr",
                   "m": ["00000001", "00000002", "00000003"], "u": ["00000004", "00000005", "00000006"]},
            "s2": {"sig": "bl CALL ; cmp r, # ; nop ; b #",
                   "m": ["00000001", "00000002", "00000003"], "u": ["00000004", "00000005", "00000006"]},
            "s3": {"sig": "str r, [r, #] ; bl CALL ; cmp r, # ; nop",
                   "m": ["00000001", "00000002", "00000003"], "u": ["00000004", "00000005", "00000006"]},
        }
        rows = shapemine.rank_clusters(motifs, min_files=1, min_unlock=1, focus="stores", top=10)
        self.assertEqual([r["id"] for r in rows], ["s1"])
        rows = shapemine.rank_clusters(motifs, min_files=1, min_unlock=1, focus="any", top=10)
        self.assertEqual(len(rows), 3)

    def test_candidate_spec_groups_examples_by_file(self):
        functions = json.loads((self.root / "functions.json").read_text())
        spec = shapemine.candidate_spec("aaa", self.motifs(), functions)
        self.assertEqual(spec["matched_files"], 2)
        self.assertEqual(spec["unindexed_overlap"], 2)
        paths = [e["path"] for e in spec["examples"]]
        self.assertEqual(paths, ["src/a.cpp", "src/b.cpp"])


class AggregateTests(unittest.TestCase):
    def test_aggregate_splits_matched_and_unindexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "functions.json").write_text(json.dumps({
                "00000001": {"status": "honest", "path": "src/a.cpp"}}))
            fn_log = root / "fn.jsonl"
            fn_log.write_text("\n".join([
                json.dumps({"addr": "00000001", "motifs": ["aa", "bb"]}),
                json.dumps({"addr": "00000002", "motifs": ["bb"]}),
            ]) + "\n")
            sigs = root / "sigs.json"
            sigs.write_text(json.dumps({"aa": "s-a", "bb": "s-b"}))
            motifs_cache = root / "motifs.json"
            with patch.object(shapemine, "ROOT", str(root)), \
                 patch.object(shapemine, "FN_LOG", str(fn_log)), \
                 patch.object(shapemine, "SIGS", str(sigs)), \
                 patch.object(shapemine, "MOTIFS", str(motifs_cache)):
                motifs = shapemine.aggregate()
                self.assertEqual(motifs["bb"], {"sig": "s-b", "m": ["00000001"], "u": ["00000002"]})
                self.assertEqual(motifs["aa"]["m"], ["00000001"])
                # second call hits the cache
                self.assertEqual(shapemine.aggregate(), motifs)


if __name__ == "__main__":
    unittest.main()
