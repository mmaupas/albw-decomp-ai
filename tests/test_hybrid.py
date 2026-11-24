import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import audit
import hybrid_build


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # .text 0x100000..0x100020, three functions of 0x10 bytes each? use 4-byte words:
        # starts 0x100000 (matched), 0x100008 (lifted), 0x100010 (unmatched), end 0x100020
        self.starts = [0x100000, 0x100008, 0x100010]
        self.functions = {
            "00100000": {"status": "honest", "path": "src/a.c", "cc": "4.1/b1049"},
            "00100008": {"status": "lifted", "path": "src_lifted/func_00100008.c", "cc": "4.1/b1049"},
            "00100010": {"status": "semantic_match", "path": "src_lifted/func_00100010.c",
                         "wall_class": "scheduling"},  # semantic_match is NOT matched bytes
        }
        patcher = patch.object(hybrid_build, "TEXT_SIZE", 0x20)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_layers_partition_functions_and_bytes(self):
        plan = hybrid_build.composition(self.functions, self.starts)
        self.assertEqual(plan["total_functions"], 3)
        self.assertEqual(plan["text_bytes"], 0x20)
        self.assertEqual(plan["layers"]["matched"], {"functions": 1, "bytes": 8})
        self.assertEqual(plan["layers"]["lifted"], {"functions": 1, "bytes": 8})
        # semantic_match falls through to original bytes: byte diffs remain
        self.assertEqual(plan["layers"]["original"], {"functions": 1, "bytes": 16})
        self.assertEqual(sum(l["bytes"] for l in plan["layers"].values()), 0x20)
        self.assertEqual(len(plan["regions"]), 1)
        reg = plan["regions"][0]
        self.assertEqual(reg["lo"], 0x100000)
        self.assertEqual((reg["matched"][1], reg["lifted"][1], reg["original"][1]), (8, 8, 16))

    def test_check_command_is_offline_and_writes_plan(self):
        (self.root / "funcs.json").write_text(json.dumps({"starts": self.starts, "bl": [], "ptr": []}))
        (self.root / "functions.json").write_text(json.dumps(self.functions))
        state = self.root / "logs" / "hybrid"
        patchers = [patch.object(hybrid_build, "ROOT", str(self.root)),
                    patch.object(hybrid_build, "STATE", str(state)),
                    patch.object(hybrid_build, "PLAN_FILE", str(state / "plan.json")),
                    patch.object(hybrid_build, "STATE_FILE", str(state / "state.json"))]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = hybrid_build.cmd_check(as_json=True)
        self.assertEqual(rc, 0)
        plan = json.loads(out.getvalue())
        self.assertEqual(plan["layers"]["lifted"]["functions"], 1)
        self.assertTrue((state / "plan.json").exists())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(hybrid_build.cmd_report(as_json=True), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["mode"], "report")
        self.assertEqual(report["layers"]["matched"]["bytes"], 8)

    def test_full_build_degrades_without_proprietary_inputs(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = hybrid_build.cmd_build(str(self.root / "build" / "hybrid.bin"))
        self.assertEqual(rc, 2)
        self.assertIn("code.bin", out.getvalue())
        self.assertIn("hybrid_build.py --out build/hybrid.bin", out.getvalue())
        self.assertFalse((self.root / "build").exists())

    def test_full_build_uses_rebuild_check_machinery_and_never_touches_code_bin(self):
        """With fake inputs present, the build imports rebuild_check, places bytes
        via its assemble_image, writes only the --out file, and records state."""
        (self.root / "funcs.json").write_text(json.dumps({"starts": self.starts, "bl": [], "ptr": []}))
        (self.root / "functions.json").write_text(json.dumps(self.functions))
        (self.root / "code.bin").write_bytes(b"\x00" * 0x20)
        lifted_src = self.root / "src_lifted" / "func_00100008.c"
        lifted_src.parent.mkdir(parents=True)
        lifted_src.write_text("/* LIFTED */\nu32 func_00100008(u32 r0) { return r0; }\n")
        exe = self.root / "tools" / "armcc" / "4.1" / "b1049" / "bin"
        exe.mkdir(parents=True)
        (exe / "armcc.exe").write_bytes(b"MZ")
        state = self.root / "logs" / "hybrid"
        image = bytes(range(0x20))
        calls = {}

        class FakeRebuild:
            fn = type("F", (), {"DEFAULT_CC": "4.1/b1049",
                                "DEFAULT_FLAGS": "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections"})()
            OBJDIR = None

            @staticmethod
            def honest_entries(include_hacks=False, limit=None):
                return [(0x100000, "src/a.c", "4.1/b1049", "flags")]

            @staticmethod
            def assemble_image(entries):
                calls["entries"] = entries
                calls["objdir"] = FakeRebuild.OBJDIR
                return image, 2

        patchers = [patch.object(hybrid_build, "ROOT", str(self.root)),
                    patch.object(hybrid_build, "STATE", str(state)),
                    patch.object(hybrid_build, "STATE_FILE", str(state / "state.json")),
                    patch.object(hybrid_build, "OBJDIR", str(state / "obj")),
                    patch.object(hybrid_build, "LOCK", str(self.root / "logs" / "compiler.lock")),
                    patch.object(hybrid_build.sys, "modules", dict(hybrid_build.sys.modules)),
                    patch.dict(hybrid_build.sys.modules, {"rebuild_check": FakeRebuild})]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        with patch.object(hybrid_build, "load_binary", return_value=b"\x00" * 0x20):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = hybrid_build.cmd_build(str(self.root / "build" / "hybrid.bin"), as_json=True)
        self.assertEqual(rc, 0)
        record = json.loads(out.getvalue())
        self.assertEqual(record["compiled"], 2)
        self.assertEqual(record["matched_entries"], 1)
        self.assertEqual(record["lifted_entries"], 1)
        self.assertEqual(record["bytes"], 0x20)
        # lifted entry passed through with its own path/cc/flags
        self.assertIn((0x100008, "src_lifted/func_00100008.c", "4.1/b1049",
                       "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections"),
                      calls["entries"])
        # separate object cache from the gate's logs/rebuild/obj
        self.assertEqual(calls["objdir"], str(state / "obj"))
        # output written only to --out; code.bin untouched
        self.assertEqual((self.root / "build" / "hybrid.bin").read_bytes(), image)
        self.assertEqual((self.root / "code.bin").read_bytes(), b"\x00" * 0x20)
        st = json.loads((state / "state.json").read_text())
        self.assertEqual(st["builds"][-1]["sha1"], __import__("hashlib").sha1(image).hexdigest())


class RepoCheckTests(unittest.TestCase):
    def test_check_runs_offline_against_real_metadata(self):
        """--check over the real funcs.json + functions.json needs no inputs."""
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = hybrid_build.cmd_check(as_json=True)
        self.assertEqual(rc, 0)
        plan = json.loads(out.getvalue())
        self.assertGreater(plan["total_functions"], 25000)
        layers = plan["layers"]
        self.assertGreater(layers["matched"]["functions"], 16000)
        lifted_now = audit.stats(audit.load())["lifted"]
        self.assertEqual(layers["lifted"]["functions"], lifted_now)
        self.assertEqual(layers["matched"]["bytes"] + layers["lifted"]["bytes"] + layers["original"]["bytes"],
                         plan["text_bytes"])


if __name__ == "__main__":
    unittest.main()
