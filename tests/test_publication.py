import contextlib
import errno
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import audit
import common
import worklist


class AtomicWriteTests(unittest.TestCase):
    def test_failure_preserves_previous_file_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("old")
            with patch.object(common.os, "replace", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    common.atomic_write(path, "new")
            self.assertEqual(path.read_text(), "old")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_canonical_metadata_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "functions.json"
            path.write_text("old")
            path.chmod(0o644)
            common.write_json(path, {"B": {}, "A": {}}, canonical=True)
            self.assertEqual(path.read_text(), audit.canonical_bytes({"B": {}, "A": {}}))
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)


class WindowsLockTests(unittest.TestCase):
    def test_contention_is_retried_until_lock_is_acquired(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = os.path.join(directory, "writer.lock")
            windows = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=Mock(
                side_effect=[OSError(errno.EACCES, "busy")] * 12 + [None, None]))
            with patch.object(common.os, "name", "nt"), patch.object(
                    common, "msvcrt", windows, create=True), patch.object(common.time, "sleep") as sleep:
                with common.file_lock(lock):
                    pass
            self.assertEqual(sleep.call_count, 12)
            self.assertEqual(windows.locking.call_count, 14)
            self.assertEqual(windows.locking.call_args.args[1], windows.LK_UNLCK)


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.auto = self.root / "src" / "work8" / "auto"
        self.auto.mkdir(parents=True)
        self.index = self.root / "functions.json"
        self.index.write_text("{}")
        self.source = self.root / "candidate.cpp"
        self.source.write_text("void func_00100000() {}\n")
        self.dest = self.auto / "func_00100000.cpp"
        self.state_dir = self.root / "logs" / "autodecomp"
        for name, value in (("ROOT", str(self.root)), ("AUTO_DIR", str(self.auto)),
                            ("STATE_DIR", str(self.state_dir)),
                            ("STATE_FILE", str(self.state_dir / "state.json"))):
            patcher = patch.object(worklist, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(worklist.fn, "STARTS", [0x100000])
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(worklist, "check_one", return_value=dict(
            match=True, err="", words=1, total=1))
        self.check = patcher.start()
        self.addCleanup(patcher.stop)

    def register(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = worklist.register(0x100000, src=str(self.source), **kwargs)
        return result, output.getvalue()

    def test_success_verifies_final_path_and_emits_one_json_value(self):
        result, output = self.register(as_json=True)
        self.assertEqual(json.loads(output), result)
        self.assertEqual(self.check.call_args.args[1], str(self.dest))
        self.assertEqual(json.loads(self.index.read_text())["00100000"]["status"], "honest")
        self.assertEqual(self.dest.read_text(), self.source.read_text())

    def test_existing_source_is_never_overwritten(self):
        self.dest.write_text("previous source")
        with self.assertRaises(FileExistsError):
            self.register()
        self.assertEqual(self.dest.read_text(), "previous source")
        self.check.assert_not_called()

    def test_existing_index_entry_is_never_replaced(self):
        self.index.write_text('{"00100000": {"status": "no_source"}}')
        with self.assertRaisesRegex(ValueError, "existing index"):
            self.register()
        self.check.assert_not_called()
        self.assertFalse(self.dest.exists())

    def test_failed_verification_preserves_index_and_removes_new_source(self):
        self.check.return_value = dict(match=False, err="", words=0, total=1)
        with self.assertRaisesRegex(ValueError, "NO MATCH"):
            self.register()
        self.assertEqual(self.index.read_text(), "{}")
        self.assertFalse(self.dest.exists())
        self.assertEqual(self.source.read_text(), "void func_00100000() {}\n")

    def test_failed_publication_does_not_leave_unregistered_source(self):
        with patch.object(worklist, "write_json", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                self.register()
        self.assertEqual(self.index.read_text(), "{}")
        self.assertFalse(self.dest.exists())

    def test_interruption_after_index_replacement_preserves_indexed_source(self):
        write_json = worklist.write_json

        def interrupted(path, data, **kwargs):
            write_json(path, data, **kwargs)
            raise KeyboardInterrupt()

        with patch.object(worklist, "write_json", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.register()
        self.assertEqual(json.loads(self.index.read_text())["00100000"]["path"],
                         os.path.relpath(self.dest, self.root))
        self.assertEqual(self.dest.read_text(), self.source.read_text())

    def test_interior_address_is_rejected_before_any_write(self):
        with self.assertRaisesRegex(ValueError, "exact function start"):
            worklist.register(0x100001, src=str(self.source))
        self.check.assert_not_called()
        self.assertFalse(self.dest.exists())

    def test_hacks_are_rejected_before_any_write(self):
        for construct in ("__schedule_barrier();", "__asm {}", "int perm_t83;", "__weak void f();",
                          "__attribute__((__weak__)) void f();",
                          "__attribute__((weak, noinline)) void f();",
                          "__attribute__((aligned(4), weak)) void f();"):
            self.source.write_text(construct)
            with self.subTest(construct=construct), self.assertRaisesRegex(ValueError, "honest registration"):
                self.register()
        self.check.assert_not_called()
        self.assertFalse(self.dest.exists())

    def test_absolute_include_on_later_line_is_rejected(self):
        self.source.write_text('int value;\n#include "/outside/header.h"\n')
        with self.assertRaisesRegex(ValueError, "PATH AUDIT"):
            self.register()
        self.check.assert_not_called()

    def test_include_rebase_preserves_trailing_text(self):
        header = str(self.root / "shared" / "header.h")
        text = '#include "%s" // explanation\n' % header
        rebased = worklist.rebase_includes(text, str(self.auto))
        self.assertIn('// explanation', rebased)
        self.assertNotIn(header, rebased)
        with self.assertRaisesRegex(ValueError, "PATH AUDIT"):
            self.source.write_text('#include "%s-elsewhere/header.h"\n' % self.root)
            self.register()

    def test_recorded_compiler_and_flags_are_preserved(self):
        state = {"cc": "4.1/b894", "best": {"flags": "--apcs=/fpic", "path": str(self.source)}}
        with patch.object(worklist, "refine_state", return_value=state):
            self.register()
        self.assertEqual(self.check.call_args.kwargs["cc"], "4.1/b894")
        self.assertEqual(self.check.call_args.args[3], "--apcs=/fpic")


class AuditTests(unittest.TestCase):
    def test_comments_and_strings_do_not_trigger_hack_checks(self):
        self.assertEqual(audit.trick_reasons('// __asm\nchar *s="perm_t83"; /* __weak */'), [])
        self.assertEqual(audit.trick_reasons('int perm_t83;'), ["perm_t"])

    def test_path_escapes_including_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            Path(root, "link").symlink_to(outside, target_is_directory=True)
            with patch.object(audit, "ROOT", root):
                for path in (outside, "../outside", "link/source.c"):
                    with self.subTest(path=path), self.assertRaises(ValueError):
                        audit.source_path(path)
                self.assertEqual(audit.source_path("src/file.c"), os.path.join(root, "src/file.c"))


if __name__ == "__main__":
    unittest.main()
