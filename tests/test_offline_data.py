import contextlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import audit
import dna
import recipes
import triage
from common import file_lock


class DerivedDataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.index = self.root / "dna.jsonl"

    def build_dna(self):
        with patch.object(dna, "DNA_FILE", str(self.index)), patch.object(
                dna.fn, "STARTS", [0x100000, 0x100004]), patch.object(
                dna, "dna_of", side_effect=lambda start, end: {"addr": "%08X" % start}), contextlib.redirect_stdout(io.StringIO()):
            dna.build_index()
            return dna.load_index()

    def test_partial_tail_is_removed_before_append(self):
        self.index.write_text('{"addr":"00100000"}\n{"addr":')
        self.assertEqual([row["addr"] for row in self.build_dna()], ["00100000", "00100004"])

    def test_valid_final_record_without_newline_is_separated(self):
        self.index.write_text('{"addr":"00100000"}')
        self.assertEqual(len(self.build_dna()), 2)

    def test_interior_corruption_is_not_silently_ignored(self):
        self.index.write_text('{"addr":"00100000"}\nbroken\n{"addr":"00100004"}\n')
        with self.assertRaisesRegex(ValueError, "before final record"):
            self.build_dna()

    def test_empty_triage_bucket_replaces_stale_candidates(self):
        (self.root / "funcs.json").write_text('{"starts":[1048576]}')
        (self.root / "functions.json").write_text('{"00100000":{"status":"honest"}}')
        output_dir = self.root / "triage"
        output_dir.mkdir()
        candidates = output_dir / "unindexed_candidate.txt"
        candidates.write_text("00100000 4\n")
        with patch.object(triage, "ROOT", str(self.root)), patch.object(
                triage, "load_binary", return_value=struct.pack("<I", 0xE12FFF1E)), patch.object(
                triage, "TS", 4), patch.object(sys, "argv", ["triage.py", "--out", str(output_dir)]), contextlib.redirect_stdout(io.StringIO()):
            triage.main()
        self.assertEqual(candidates.read_text(), "")
        self.assertTrue(all((output_dir / ("unindexed_%s.txt" % name)).exists() for name in triage.CLASSES))

    def test_recipe_json_has_no_prose(self):
        corpus = self.root / "recipes.json"
        corpus.write_text('[{"id":"example","kind":"positive","shape":"strd","source":"stores"}]')
        with patch.object(recipes, "CORPUS", str(corpus)), contextlib.redirect_stdout(io.StringIO()) as output:
            recipes.query(SimpleNamespace(signature="strd", json=True))
        self.assertEqual(json.loads(output.getvalue())[0]["id"], "example")

    def test_statistics_partition_functions_and_text_bytes(self):
        (self.root / "funcs.json").write_text('{"starts":[1048576,1048580,1048584]}')
        data = {"00100000": {"status": "honest"}, "00100004": {"status": "excluded_library"},
                "00100002": {"status": "interior_address"}}
        with patch.object(audit, "ROOT", str(self.root)), patch.object(audit, "TEXT_SIZE", 12):
            stats = audit.stats(data)
        self.assertEqual(stats["unmatched"], 1)
        self.assertEqual(stats["interior_address"], 1)
        self.assertEqual(stats["remaining_honest"], 1)
        self.assertEqual(sum(stats["bytes_by_status"].values()), 12)
        self.assertEqual(stats["bytes_by_status"]["honest"], 4)

    def test_generated_readme_can_be_checked_and_refreshed(self):
        readme = self.root / "README.md"
        readme.write_text("prefix\n<!-- generated:status -->old<!-- /generated:status -->\n"
                          "<!-- generated:arabic-status -->old<!-- /generated:arabic-status -->\nsuffix\n")
        with patch.object(audit, "ROOT", str(self.root)), patch.object(
                audit, "readme_blocks", return_value={"status": "new", "arabic-status": "same numbers"}):
            self.assertFalse(audit.update_readme({}))
            self.assertIn("old", readme.read_text())
            audit.update_readme({}, write=True)
            self.assertTrue(audit.update_readme({}))
        self.assertTrue(readme.read_text().endswith("suffix\n"))


class OfflineAndLockTests(unittest.TestCase):
    def test_reporting_without_binary_compiler_or_site_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            for source in (ROOT / "tools").glob("*.py"):
                shutil.copy(source, root / "tools" / source.name)
            (root / "functions.json").write_text("{}")
            (root / "funcs.json").write_text('{"starts":[1048576],"bl":[],"ptr":[]}')
            for command in ("status", "report"):
                result = subprocess.run([sys.executable, "-S", "tools/worklist.py", command, "--json"],
                                        cwd=root, capture_output=True, text=True, check=True)
                json.loads(result.stdout)
            self.assertFalse((root / "code.bin").exists())
            self.assertFalse((root / "logs").exists())

    def test_publication_lock_excludes_another_process(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "shared.lock"
            marker = Path(directory) / "acquired"
            script = ("import sys; from pathlib import Path; "
                      "sys.path.insert(0, sys.argv[1]); from common import file_lock; "
                      "print('ready', flush=True)\n"
                      "with file_lock(sys.argv[2]): Path(sys.argv[3]).write_text('acquired')\n")
            with file_lock(lock):
                process = subprocess.Popen([sys.executable, "-c", script, str(ROOT / "tools"), str(lock), str(marker)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertEqual(process.stdout.readline().strip(), "ready")
                self.assertFalse(marker.exists())
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(marker.read_text(), "acquired")


if __name__ == "__main__":
    unittest.main()
