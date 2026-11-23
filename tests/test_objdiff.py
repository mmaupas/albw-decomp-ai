"""objdiff-cli wrapper (roadmap H2): tools/objdiff.py degrades to the exact
setup command + exit 2 when the binary or the objects are absent, and emits
machine-readable --json diffs/units otherwise. All tests mock the subprocess
(no binary, no network, no objects needed); the real pinned binary is only
smoke-tested manually on the phone/host, never in CI.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import objdiff
import setup_objdiff

DIFF_JSON = {
    "left": {"sections": [{"name": ".text", "kind": "SECTION_CODE", "size": "82",
                           "match_percent": 97.0},
                          {"name": ".rodata", "kind": "SECTION_DATA", "size": "16",
                           "match_percent": 100.0,
                           "data_diff": [{"data": "AQAAAA==", "size": "4"}]}],
             "symbols": [{"name": "add", "kind": "SYMBOL_FUNCTION", "size": "20",
                          "match_percent": 100.0},
                         {"name": "mul", "kind": "SYMBOL_FUNCTION", "size": "22",
                          "match_percent": 88.9}]},
    "right": {"sections": [], "symbols": [{"name": "add", "kind": "SYMBOL_FUNCTION",
                                           "match_percent": 100.0}]},
}


class ObjdiffFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "tools" / "bin" / "objdiff-cli"
        self.bin.parent.mkdir(parents=True)
        self.base = self.root / "base.o"
        self.target = self.root / "target.o"
        self.base.write_bytes(b"\x7fELF-base")
        self.target.write_bytes(b"\x7fELF-target")

    def install_fake_binary(self):
        self.bin.write_bytes(b"#!/fake\n")
        return str(self.bin)

    def run_cli(self, argv, stdout="", rc=0, stderr=""):
        """Run objdiff.main with a mocked subprocess; returns (exit, popen-args, stdout)."""
        proc = Mock(returncode=rc, stdout=stdout, stderr=stderr)
        with patch.object(objdiff, "ROOT", str(self.root)), patch.object(
                objdiff.subprocess, "run", return_value=proc) as run, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = objdiff.main(argv)
        return code, run.call_args.args[0], out.getvalue()

    def capture(self, fn, *args, **kwargs):
        with patch.object(objdiff, "ROOT", str(self.root)), contextlib.redirect_stdout(
                io.StringIO()) as out:
            code = fn(*args, **kwargs)
        return code, out.getvalue()


class DegradationTests(ObjdiffFixture):
    def test_missing_binary_exits_2_with_setup_command(self):
        code, out = self.capture(objdiff.main, ["diff", str(self.base), str(self.target), "--json"])
        self.assertEqual(code, 2)
        self.assertIn("python3 tools/setup_objdiff.py", out)
        self.assertIn("--target linux-aarch64", out)
        self.assertIn("tools/bin/objdiff-cli", out)

    def test_missing_objects_exit_2_with_setup_command(self):
        self.install_fake_binary()
        code, out = self.capture(objdiff.main, ["units", str(self.root / "nope.o")])
        self.assertEqual(code, 2)
        self.assertIn("python3 tools/setup_objdiff.py", out)
        self.assertIn("nope.o", out)

    def test_diff_missing_target_object_mentions_it(self):
        self.install_fake_binary()
        code, out = self.capture(objdiff.main, ["diff", str(self.base), str(self.root / "gone.o")])
        self.assertEqual(code, 2)
        self.assertIn("gone.o", out)

    def test_binary_path_respects_root(self):
        with patch.object(objdiff, "ROOT", str(self.root)):
            self.assertEqual(objdiff.binary_path(), str(self.bin))


class DiffCommandTests(ObjdiffFixture):
    def test_json_diff_reemits_the_tools_own_json(self):
        self.install_fake_binary()
        code, argv, out = self.run_cli(["diff", str(self.base), str(self.target), "--json"],
                                       stdout=json.dumps(DIFF_JSON))
        self.assertEqual(code, 0)
        self.assertEqual(argv[1:4], ["diff", "-2", str(self.base)])
        self.assertEqual(argv[argv.index("-1") + 1], str(self.target))
        self.assertEqual(argv[argv.index("-o") + 1], "-")
        self.assertEqual(argv[argv.index("--format") + 1], "json")
        self.assertEqual(json.loads(out), DIFF_JSON)

    def test_json_falls_back_to_structured_passthrough(self):
        self.install_fake_binary()
        with patch.object(objdiff, "ROOT", str(self.root)), patch.object(
                objdiff.subprocess, "run", return_value=Mock(
                    returncode=3, stdout="not json at all", stderr="boom")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = objdiff.main(["diff", str(self.base), str(self.target), "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["tool"], "objdiff-cli")
        self.assertEqual(payload["returncode"], 3)
        self.assertEqual(payload["stdout"], "not json at all")
        self.assertEqual(payload["stderr"], "boom")
        self.assertIn("diff", payload["command"])

    def test_text_diff_summarizes_units_and_sections(self):
        self.install_fake_binary()
        with patch.object(objdiff, "ROOT", str(self.root)), patch.object(
                objdiff.subprocess, "run", return_value=Mock(
                    returncode=0, stdout=json.dumps(DIFF_JSON), stderr="")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = objdiff.main(["diff", str(self.base), str(self.target)])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("base=%s" % self.base, text)
        self.assertIn("mul", text)
        self.assertIn("match=88.90%", text)
        self.assertIn(".rodata", text)
        self.assertIn("data_diff=1 block(s)", text)

    def test_symbol_filter_is_forwarded(self):
        self.install_fake_binary()
        code, argv, _out = self.run_cli(
            ["diff", str(self.base), str(self.target), "--symbol", "mul", "--json"],
            stdout=json.dumps(DIFF_JSON))
        self.assertEqual(code, 0)
        self.assertEqual(argv[-1], "mul")


class UnitsCommandTests(ObjdiffFixture):
    def test_units_json_lists_symbols_and_sections(self):
        self.install_fake_binary()
        code, argv, out = self.run_cli(["units", str(self.base), "--json"],
                                       stdout=json.dumps(DIFF_JSON))
        self.assertEqual(code, 0)
        self.assertEqual(argv[argv.index("-2") + 1], str(self.base))
        self.assertEqual(argv[argv.index("-1") + 1], str(self.base))
        payload = json.loads(out)
        self.assertEqual(payload["object"], str(self.base))
        names = {u["name"]: u for u in payload["units"]}
        self.assertEqual(names["mul"]["match_percent"], 88.9)
        self.assertEqual(names["add"]["size"], 20)
        sections = {s["name"]: s for s in payload["sections"]}
        self.assertEqual(sections[".rodata"]["data_diff_blocks"], 1)
        self.assertEqual(sections[".text"]["match_percent"], 97.0)

    def test_units_text_output(self):
        self.install_fake_binary()
        with patch.object(objdiff, "ROOT", str(self.root)), patch.object(
                objdiff.subprocess, "run", return_value=Mock(
                    returncode=0, stdout=json.dumps(DIFF_JSON), stderr="")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = objdiff.main(["units", str(self.base)])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("units in %s" % self.base, text)
        self.assertIn("mul", text)
        self.assertIn("match=88.90%", text)

    def test_units_passthrough_when_output_resists_parsing(self):
        self.install_fake_binary()
        with patch.object(objdiff, "ROOT", str(self.root)), patch.object(
                objdiff.subprocess, "run", return_value=Mock(
                    returncode=0, stdout="garbage", stderr="")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = objdiff.main(["units", str(self.base), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["object"], str(self.base))
        self.assertEqual(payload["raw"]["stdout"], "garbage")


class SetupObjdiffTests(unittest.TestCase):
    FAKE = b"fake objdiff-cli binary bytes"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.dest = Path(self.temporary.name) / "bin"
        self.pinned = {"linux-x86_64": ("fake-asset", hashlib.sha256(self.FAKE).hexdigest()),
                       "linux-aarch64": ("fake-asset-arm", hashlib.sha256(b"arm").hexdigest())}

    def fake_opener(self, payload):
        def opener(request, timeout=None):
            self.requested = request.full_url
            import io as _io
            return _io.BytesIO(payload)
        return opener

    def test_install_verifies_hash_and_writes_sidecar(self):
        with patch.object(setup_objdiff, "ASSETS", self.pinned):
            dest, got = setup_objdiff.install("linux-x86_64", dest_dir=str(self.dest),
                                              opener=self.fake_opener(self.FAKE))
        self.assertEqual(Path(dest).read_bytes(), self.FAKE)
        self.assertEqual(got, self.pinned["linux-x86_64"][1])
        self.assertTrue(os.access(dest, os.X_OK))
        sidecar = json.loads((self.dest / "objdiff-cli.json").read_text())
        self.assertEqual(sidecar["version"], setup_objdiff.OBJDIFF_VERSION)
        self.assertEqual(sidecar["target"], "linux-x86_64")
        self.assertEqual(sidecar["sha256"], got)
        self.assertIn("v3.8.3", self.requested)
        self.assertIn("fake-asset", self.requested)
        result = setup_objdiff.check(str(self.dest))
        self.assertTrue(result["ok"])
        self.assertEqual(result["version"], "v3.8.3")

    def test_hash_mismatch_refuses_and_leaves_nothing(self):
        bad = {"linux-x86_64": ("fake-asset", "0" * 64)}
        with patch.object(setup_objdiff, "ASSETS", bad):
            with self.assertRaises(SystemExit) as ctx:
                setup_objdiff.install("linux-x86_64", dest_dir=str(self.dest),
                                      opener=self.fake_opener(self.FAKE))
        self.assertIn("SHA-256 mismatch", str(ctx.exception))
        self.assertFalse((self.dest / "objdiff-cli").exists())
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_unknown_target_is_rejected(self):
        with self.assertRaises(SystemExit):
            setup_objdiff.install("linux-mips", dest_dir=str(self.dest),
                                  opener=self.fake_opener(self.FAKE))

    def test_check_reports_missing_binary(self):
        self.assertIsNone(setup_objdiff.check(str(self.dest)))

    def test_detect_target_mapping(self):
        self.assertEqual(setup_objdiff.detect_target("linux", "x86_64"), "linux-x86_64")
        self.assertEqual(setup_objdiff.detect_target("linux", "AMD64"), "linux-x86_64")
        self.assertEqual(setup_objdiff.detect_target("linux", "aarch64"), "linux-aarch64")
        self.assertEqual(setup_objdiff.detect_target("darwin", "arm64"), "macos-arm64")
        self.assertEqual(setup_objdiff.detect_target("darwin", "x86_64"), "macos-x86_64")
        self.assertEqual(setup_objdiff.detect_target("win32", "AMD64"), "windows-x86_64")
        with self.assertRaises(SystemExit):
            setup_objdiff.detect_target("plan9", "sparc")

    def test_pinned_release_records_version_and_hashes(self):
        self.assertEqual(setup_objdiff.OBJDIFF_VERSION, "v3.8.3")
        for target, (asset, digest) in setup_objdiff.ASSETS.items():
            self.assertEqual(len(digest), 64)
            self.assertIn(asset, setup_objdiff.RELEASE_URL % (setup_objdiff.OBJDIFF_VERSION, asset))
        self.assertIn("linux-aarch64", setup_objdiff.ASSETS)  # the phone


if __name__ == "__main__":
    unittest.main()
