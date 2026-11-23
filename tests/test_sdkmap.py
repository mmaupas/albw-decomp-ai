import contextlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import audit
import sdkmap


# The offline CI workflow runs stdlib-only (no capstone); every test that
# actually disassembles is skipped there and runs under `uv run` (uv sync).
needs_capstone = unittest.skipIf(sdkmap.Cs is None,
                                 "capstone not installed (uv sync); stdlib-only runs skip this")


VEC3_CPP = '''#include <nn/math/math_VEC3.h>

namespace nn {
namespace math {
    namespace ARMv6 {

    __asm void __attribute__((section("i._ZN2nn4math5ARMv610VEC3SubAsmEPNS0_4VEC3EPKS2_S5_"))) VEC3SubAsm(VEC3* out, const VEC3* v1, const VEC3* v2)
    {
        bx lr
    }

    } // namespace ARMv6
} // namespace math
} // namespace nn
'''

VEC3_H = '''#pragma once

namespace nn {
namespace math {

    struct VEC3 {
        float x;
        float y;
        float z;
    };

    namespace ARMv6 {

        void VEC3AddAsm(VEC3* out, const VEC3* v1, const VEC3* v2);
        void VEC3SubAsm(VEC3* out, const VEC3* v1, const VEC3* v2);
        void VEC3MulAsm(VEC3* out, const VEC3* v1, float f);

    } // namespace ARMv6

} // namespace math
} // namespace nn
'''

HANDLE_H = '''#pragma once

namespace nn {

struct Handle {
    u32 m_Handle;
    Handle()
        : m_Handle(0)
    {
    }
};

} // namespace nn
'''

RESULT_H = '''#pragma once

namespace nn {

class Result {
    s32 mValue;

public:
    enum Level {
        Level_Success = 0,
        Level_Fatal = -1
    };

    Result();
    Result(Level level, int module);
    virtual ~Result();
    bool Succeeded() const;
    static Result MakeFailure();
    operator bool() const;
};

} // namespace nn
'''

SVC_API_H = '''#pragma once

namespace nn {
namespace svc {
    __asm nn::Result ControlMemory(u32* addr, u32 size);
    __asm void ExitProcess();
    __asm nn::Result CreateMutex(nn::Handle* mutex, bool initialLocked);
}
}
'''


def make_nnsdk_tree(root):
    """Synthetic nnsdk-like tree (no real nnsdk content)."""
    files = {
        "Source/math/math_VEC3.cpp": VEC3_CPP,
        "Include/nn/math/math_VEC3.h": VEC3_H,
        "Include/nn/Handle.h": HANDLE_H,
        "Include/nn/Result.h": RESULT_H,
        "Include/nn/svc/svc_Api.h": SVC_API_H,
        ".git/ignored.cpp": "namespace nn { void Hidden(); }\n",
        "logs/scratch.cpp": "namespace nn { void Scratch(); }\n",
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def make_inventory():
    """Inventory dict as produced by scan_nnsdk over the synthetic tree."""
    tmp = tempfile.TemporaryDirectory()
    tree = make_nnsdk_tree(Path(tmp.name))
    inv, _cache = sdkmap.scan_nnsdk(str(tree))
    tmp.cleanup()
    return inv


class InventoryParseTests(unittest.TestCase):
    def test_kinds_and_qualified_names(self):
        funcs, types = sdkmap.parse_file(RESULT_H, "Include/nn/Result.h")
        by_name = {}
        for f in funcs:
            by_name.setdefault(f["name"], []).append(f)
        self.assertEqual(by_name["Result"][0]["kind"], "constructor")
        self.assertEqual(by_name["~Result"][0]["kind"], "destructor")
        self.assertEqual(by_name["Succeeded"][0]["kind"], "member")
        self.assertEqual(by_name["MakeFailure"][0]["kind"], "static_member")
        self.assertEqual(by_name["operator bool"][0]["kind"], "member_operator")
        self.assertIn("Result", types)
        # enum members are not functions
        self.assertNotIn("Level", by_name)
        self.assertNotIn("Level_Success", by_name)

    def test_ctor_initializer_list_is_not_a_function(self):
        funcs, _types = sdkmap.parse_file(HANDLE_H, "Include/nn/Handle.h")
        self.assertEqual([f["name"] for f in funcs], ["Handle"])
        self.assertEqual(funcs[0]["kind"], "constructor")

    def test_asm_section_yields_exact_mangled_name(self):
        funcs, _types = sdkmap.parse_file(VEC3_CPP, "Source/math/math_VEC3.cpp")
        self.assertEqual(len(funcs), 1)
        fn = funcs[0]
        self.assertTrue(fn["asm"])
        self.assertEqual(fn["kind"], "free_function")
        self.assertEqual(fn["qualified"], "nn::math::ARMv6::VEC3SubAsm")
        self.assertEqual(fn["mangled_exact"],
                         "_ZN2nn4math5ARMv610VEC3SubAsmEPNS0_4VEC3EPKS2_S5_")

    def test_mangled_patterns(self):
        inv = make_inventory()
        pats = {}
        for f in inv["files"]:
            for fn in f["functions"]:
                pats.setdefault(fn["qualified"], []).append(fn["mangled_pattern"])
        self.assertEqual(pats["nn::svc::ExitProcess"], ["_ZN2nn3svc11ExitProcessEv"])
        self.assertEqual(pats["nn::svc::CreateMutex"],
                         ["_ZN2nn3svc11CreateMutexEPN2nn6HandleEb"])
        self.assertEqual(pats["nn::Result::Result"], ["_ZN2nn6ResultC1Ev",
                                                      "_ZN2nn6ResultC1EN2nn5LevelEi"])
        self.assertEqual(pats["nn::Result::~Result"], ["_ZN2nn6ResultD1Ev"])
        self.assertEqual(pats["nn::Result::operator bool"], ["_ZN2nn6ResultbEv"])
        self.assertEqual(pats["nn::math::ARMv6::VEC3MulAsm"],
                         ["_ZN2nn4math5ARMv610VEC3MulAsmEPN2nn4math4VEC3EPKN2nn4math4VEC3Ef"])
        self.assertEqual(pats["nn::math::ARMv6::VEC3AddAsm"],
                         ["_ZN2nn4math5ARMv610VEC3AddAsmEPN2nn4math4VEC3EPKN2nn4math4VEC3EPKN2nn4math4VEC3E"])
        self.assertEqual(pats["nn::Handle::Handle"], ["_ZN2nn6HandleC1Ev"])

    def test_line_numbers_survive_stripping(self):
        funcs, _ = sdkmap.parse_file(SVC_API_H, "Include/nn/svc/svc_Api.h")
        lines = {f["name"]: f["line"] for f in funcs}
        self.assertEqual(lines, {"ControlMemory": 5, "ExitProcess": 6,
                                 "CreateMutex": 7})

    def test_skip_dirs_are_not_scanned(self):
        inv = make_inventory()
        paths = [f["path"] for f in inv["files"]]
        self.assertEqual(paths, sorted(paths))
        self.assertNotIn(".git/ignored.cpp", paths)
        self.assertNotIn("logs/scratch.cpp", paths)
        self.assertEqual(inv["counts"]["files"], 5)


class ScanInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tree = make_nnsdk_tree(Path(self.tmp.name) / "nnsdk")

    def test_deterministic_and_resumable(self):
        inv1, cache1 = sdkmap.scan_nnsdk(str(self.tree))
        inv2, cache2 = sdkmap.scan_nnsdk(str(self.tree), cache1)
        self.assertEqual(json.dumps(inv1, sort_keys=True),
                         json.dumps(inv2, sort_keys=True))
        # a comment-only change keeps the structure hash, a new function changes it
        h_before = {f["path"]: f["structure_hash"] for f in inv1["files"]}
        vec3 = self.tree / "Include/nn/math/math_VEC3.h"
        vec3.write_text(VEC3_H.replace("    } // namespace ARMv6",
                                       "    // comment\n    } // namespace ARMv6"))
        inv3, cache3 = sdkmap.scan_nnsdk(str(self.tree), cache2)
        h_after = {f["path"]: f["structure_hash"] for f in inv3["files"]}
        self.assertEqual(h_before, h_after)
        vec3.write_text(VEC3_H.replace("        void VEC3MulAsm(VEC3* out, const VEC3* v1, float f);",
                                       "        void VEC3MulAsm(VEC3* out, const VEC3* v1, float f);\n"
                                       "        void VEC3NormAsm(VEC3* out, const VEC3* v);"))
        inv4, _ = sdkmap.scan_nnsdk(str(self.tree), cache3)
        h4 = {f["path"]: f["structure_hash"] for f in inv4["files"]}
        self.assertNotEqual(h_after["Include/nn/math/math_VEC3.h"],
                            h4["Include/nn/math/math_VEC3.h"])
        self.assertEqual(h_after["Include/nn/Handle.h"], h4["Include/nn/Handle.h"])
        self.assertEqual(inv4["counts"]["functions"], inv1["counts"]["functions"] + 1)

    def test_cmd_inventory_writes_deterministic_out_and_degrades(self):
        tmp = Path(self.tmp.name)
        state = tmp / "logs" / "sdkmap"
        out = tmp / "inv.json"
        patchers = [patch.object(sdkmap, "STATE", str(state)),
                    patch.object(sdkmap, "CACHE_FILE", str(state / "inventory_cache.json")),
                    patch.object(sdkmap, "ROOT", str(tmp))]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_inventory(str(self.tree), str(out), as_json=True)
        self.assertEqual(rc, 0)
        summary = json.loads(buf.getvalue())
        self.assertEqual(summary["files"], 5)
        first = out.read_text()
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sdkmap.cmd_inventory(str(self.tree), str(out), as_json=False)
        self.assertEqual(rc, 0)
        self.assertEqual(first, out.read_text())  # deterministic bytes
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_inventory(str(tmp / "nope"), str(out), as_json=True)
        self.assertEqual(rc, 2)
        err = json.loads(buf.getvalue())
        self.assertIn("phone_commands", err)
        self.assertIn("3dsdecomp/nnsdk", err["phone_commands"])


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inv = make_inventory()
        self.starts = [0x100000, 0x100010, 0x100020, 0x100040, 0x100080,
                       0x100100, 0x100200, 0x101000, 0x105000]
        self.funcs = {"starts": self.starts, "bl": [0x100020, 0x100040], "ptr": []}
        self.functions = {
            "00100010": {"status": "excluded_library"},
            "00100040": {"status": "excluded_library"},
            "00100020": {"status": "honest", "path": "src/x.c", "cc": "4.1/b1049",
                         "hack_reasons": []},
            "00100080": {"status": "no_source", "label": "source_lost",
                         "note": "source lost"},
        }
        self.symbols = {
            0x100020: "nn::math::ARMv6 VEC3 helper (matched)",
            0x100100: "nn::math MTX34 inverse",
            0x105000: "sead::ListNode::erase_()",
        }
        (self.root / "funcs.json").write_text(json.dumps(self.funcs))
        (self.root / "functions.json").write_text(json.dumps(self.functions))
        (self.root / "symbols.jsonl").write_text("".join(
            json.dumps({"addr": "%08X" % a, "name": n}) + "\n" for a, n in self.symbols.items()))
        (self.root / "inv.json").write_text(json.dumps(self.inv))
        self.state = self.root / "logs" / "sdkmap"
        patchers = [
            patch.object(sdkmap, "ROOT", str(self.root)),
            patch.object(sdkmap, "STATE", str(self.state)),
            patch.object(sdkmap, "PLAN_FILE", str(self.state / "plan.json")),
            patch.object(sdkmap, "FINGER_FILE", str(self.state / "fingerprints.json")),
            patch.object(sdkmap, "ATTEMPTS_FILE", str(self.state / "attempts.jsonl")),
            patch.object(sdkmap, "BUILD_DIR", str(self.state / "build")),
            patch.object(sdkmap, "INVENTORY", str(self.root / "inv.json")),
            patch.object(sdkmap, "FUNCS", str(self.root / "funcs.json")),
            patch.object(sdkmap, "FUNCTIONS", str(self.root / "functions.json")),
            patch.object(sdkmap, "SYMBOLS", str(self.root / "symbols.jsonl")),
            patch.object(sdkmap, "CODE_BIN", str(self.root / "code.bin")),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def plan(self, filters=("excluded_library", "unmatched"), limit=0, fingerprints=None):
        return sdkmap.plan_rows(self.inv, self.funcs, self.functions,
                                self.symbols, filters, limit, fingerprints)

    def test_excluded_library_pool_ranks_first(self):
        rows = self.plan()
        self.assertTrue(rows)
        self.assertEqual(rows[0]["pool"], "excluded_library")
        self.assertGreaterEqual(rows[0]["score"], 100.0)
        for r in rows:
            self.assertIn(r["pool"], ("excluded_library", "unmatched"))
            for key in ("addr", "size", "size_class", "score", "reasons",
                        "name_hits", "suggested", "difficulty"):
                self.assertIn(key, r)
        excl = [r for r in rows if r["pool"] == "excluded_library"]
        self.assertEqual({r["addr"] for r in excl}, {"00100010", "00100040"})

    def test_name_hits_give_reasons_and_suggested_paths(self):
        rows = self.plan()
        hit = next(r for r in rows if r["addr"] == "00100100")
        self.assertTrue(any("name hit" in x for x in hit["reasons"]))
        self.assertIn("nn::math::ARMv6::VEC3AddAsm", hit["name_hits"])
        self.assertIn("Include/nn/math/math_VEC3.h", hit["suggested"])
        # sead:: is not in the nnsdk inventory: no hits, no suggestions
        sead = next(r for r in rows if r["addr"] == "00105000")
        self.assertEqual(sead["name_hits"], [])
        self.assertEqual(sead["suggested"], [])

    def test_size_class_and_region_signals(self):
        rows = self.plan(filters=("excluded_library", "unmatched", "source_lost"))
        near = next(r for r in rows if r["addr"] == "00100080")
        # 0x100080 is within 0x4000 of the excluded_library entries
        self.assertTrue(any("library region" in x for x in near["reasons"]))
        # the excluded_library pool defines the SDK-typical size classes
        tiny = next(r for r in rows if r["addr"] == "00100010")  # 16 B
        self.assertEqual(tiny["size_class"], "tiny")
        self.assertTrue(any("SDK-typical" in x for x in tiny["reasons"]))
        # source_lost pool only with the right filter
        rows_sl = self.plan(filters=("source_lost",))
        self.assertEqual([r["addr"] for r in rows_sl], ["00100080"])
        self.assertTrue(any("source_lost" in x for x in rows_sl[0]["reasons"]))

    def test_fingerprint_call_edges_feed_neighborhood(self):
        fingerprints = {"00100200": {"calls": ["00100040"]}}
        rows = self.plan(fingerprints=fingerprints)
        row = next(r for r in rows if r["addr"] == "00100200")
        self.assertTrue(any("calls SDK-looking" in x for x in row["reasons"]))

    def test_deterministic_order_and_limit(self):
        rows = self.plan()
        again = self.plan()
        self.assertEqual([r["addr"] for r in rows], [r["addr"] for r in again])
        keys = [(-r["score"], int(r["addr"], 16)) for r in rows]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(self.plan(limit=2)), 2)

    def test_cmd_plan_writes_state_and_json(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_plan(["excluded_library", "unmatched"], 10, as_json=True)
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["n_candidates"], 7)  # 2 excluded_library + 5 unmatched
        self.assertTrue((self.state / "plan.json").exists())
        state = json.loads((self.state / "plan.json").read_text())
        self.assertEqual(state["inventory_revision"], out["inventory_revision"])

    def test_cmd_plan_missing_inventory_degrades(self):
        os.unlink(self.root / "inv.json")
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_plan(["all"], 0, as_json=True)
        self.assertEqual(rc, 2)
        self.assertIn("inventory", json.loads(buf.getvalue())["error"])


class RealRepoPlanTests(unittest.TestCase):
    """`sdkmap plan` must run fully offline against the repo's own committed
    metadata and return a non-empty ranked candidate list."""

    def test_plan_over_real_metadata_is_non_empty_and_excludes_matched(self):
        inv = sdkmap.load_inventory()
        self.assertIsNotNone(inv, "shared/nnsdk_inventory.json must be committed")
        funcs = json.loads((ROOT / "funcs.json").read_text())
        functions = json.loads((ROOT / "functions.json").read_text())
        symbols = sdkmap.load_symbols(ROOT / "shared" / "symbols.jsonl")
        rows = sdkmap.plan_rows(inv, funcs, functions, symbols,
                                ["excluded_library", "unmatched"], 0)
        self.assertTrue(rows)
        starts = {"%08X" % a for a in funcs["starts"]}
        excluded = {k for k, v in functions.items()
                    if v.get("status") == "excluded_library"}
        self.assertTrue(excluded)
        self.assertTrue(excluded <= {r["addr"] for r in rows})
        for r in rows:
            self.assertIn(r["addr"], starts)
            ent = functions.get(r["addr"], {})
            self.assertNotIn(ent.get("status"),
                             ("honest", "hack", "lifted", "semantic_match"))
            self.assertTrue(r["reasons"])
        keys = [(-r["score"], int(r["addr"], 16)) for r in rows]
        self.assertEqual(keys, sorted(keys))


def asm(*words):
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)


def build_image():
    """Synthetic ARM image (no game content): F0 leaf + F1 caller with a pool."""
    ta = 0x100000
    f0 = asm(0xE1A04000, 0xE2800007, 0xE12FFF1E)  # mov r4,r0; add r0,r0,#7; bx lr
    f1_addr = ta + len(f0)
    bl_off = (ta - (f1_addr + 8 + 8)) >> 2
    f1 = asm(0xE92D4010, 0xE1A04000, 0xEB000000 | (bl_off & 0xFFFFFF),
             0xE59F0004, 0xE0800004, 0xE8BD8010, 0xDEADBEEF)  # ldr r0,[pc,#4] -> pool word
    data = f0 + f1
    return sdkmap.Image(data, ta), [ta, f1_addr]


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.img, self.starts = build_image()
        self.image_path = self.root / "fixture.bin"
        self.image_path.write_bytes(self.img.data)
        (self.root / "funcs.json").write_text(
            json.dumps({"starts": self.starts, "bl": [self.starts[0]], "ptr": []}))
        self.state = self.root / "logs" / "sdkmap"
        patchers = [
            patch.object(sdkmap, "ROOT", str(self.root)),
            patch.object(sdkmap, "STATE", str(self.state)),
            patch.object(sdkmap, "PLAN_FILE", str(self.state / "plan.json")),
            patch.object(sdkmap, "FINGER_FILE", str(self.state / "fingerprints.json")),
            patch.object(sdkmap, "ATTEMPTS_FILE", str(self.state / "attempts.jsonl")),
            patch.object(sdkmap, "FUNCS", str(self.root / "funcs.json")),
            patch.object(sdkmap, "CODE_BIN", str(self.root / "code.bin")),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_missing_code_bin_degrades_with_phone_command(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_fingerprint([self.starts[1]], 10, None, False, False)
        self.assertEqual(rc, 2)
        self.assertIn("code.bin", buf.getvalue())
        self.assertIn("sdkmap.py fingerprint --budget", buf.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_fingerprint([self.starts[1]], 10, None, False, True)
        self.assertEqual(rc, 2)
        out = json.loads(buf.getvalue())
        self.assertTrue(any("code.bin" in m for m in out["missing"]))
        self.assertIn("phone_commands", out)

    @needs_capstone
    def test_fingerprint_writes_resumable_state(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                rc = sdkmap.cmd_fingerprint([], 10, str(self.image_path), False, True)
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["fingerprinted_this_run"], 0)  # no plan state -> no addrs
        with contextlib.redirect_stderr(io.StringIO()):
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                rc = sdkmap.cmd_fingerprint([self.starts[0], self.starts[1]], 10,
                                            str(self.image_path), False, True)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["fingerprinted_this_run"], 2)
        fp = json.loads((self.state / "fingerprints.json").read_text())
        self.assertEqual(set(fp), {"%08X" % s for s in self.starts})
        rec = fp["%08X" % self.starts[1]]
        self.assertIn("bl CALL", rec["tokens"])
        self.assertIn("ldr r, POOL", rec["tokens"])
        self.assertEqual(rec["calls"], ["%08X" % self.starts[0]])
        self.assertGreaterEqual(rec["n_blocks"], 1)
        self.assertEqual(rec["pool_size"], 1)
        self.assertEqual(rec["n_insns"], 6)  # pool word excluded from the instruction stream
        # resumable: nothing new on a second run
        with contextlib.redirect_stderr(io.StringIO()):
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                sdkmap.cmd_fingerprint([self.starts[0]], 10, str(self.image_path), False, True)
        self.assertEqual(json.loads(buf.getvalue())["fingerprinted_this_run"], 0)

    @needs_capstone
    def test_fingerprint_one_requires_exact_start(self):
        with self.assertRaises(ValueError):
            sdkmap.fingerprint_one(self.img, self.starts, self.starts[0] + 4)


class TryCompileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.starts = [0x100000, 0x100010, 0x100020]
        (self.root / "funcs.json").write_text(
            json.dumps({"starts": self.starts, "bl": [], "ptr": []}))
        (self.root / "functions.json").write_text(json.dumps(
            {"00100020": {"status": "excluded_library"}}))
        self.state = self.root / "logs" / "sdkmap"
        self.state.mkdir(parents=True)
        self.nnsdk = make_nnsdk_tree(self.root / "nnsdk")
        (self.state / "plan.json").write_text(json.dumps({"candidates": [
            {"addr": "00100010", "suggested": ["Include/nn/math/math_VEC3.h"],
             "reasons": ["test"], "score": 1.0}]}))
        # fake game binary + compiler presence
        (self.root / "code.bin").write_bytes(b"x" * 6455296)
        armcc = self.root / "tools" / "armcc" / "4.1" / "b1049" / "bin" / "armcc.exe"
        armcc.parent.mkdir(parents=True)
        armcc.write_bytes(b"MZ")
        patchers = [
            patch.object(sdkmap, "ROOT", str(self.root)),
            patch.object(sdkmap, "STATE", str(self.state)),
            patch.object(sdkmap, "PLAN_FILE", str(self.state / "plan.json")),
            patch.object(sdkmap, "FINGER_FILE", str(self.state / "fingerprints.json")),
            patch.object(sdkmap, "ATTEMPTS_FILE", str(self.state / "attempts.jsonl")),
            patch.object(sdkmap, "BUILD_DIR", str(self.state / "build")),
            patch.object(sdkmap, "INVENTORY", str(self.root / "inv.json")),
            patch.object(sdkmap, "FUNCS", str(self.root / "funcs.json")),
            patch.object(sdkmap, "FUNCTIONS", str(self.root / "functions.json")),
            patch.object(sdkmap, "SYMBOLS", str(self.root / "symbols.jsonl")),
            patch.object(sdkmap, "CODE_BIN", str(self.root / "code.bin")),
            patch.object(sdkmap, "load_binary", lambda path: b"x" * 6455296),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_missing_prereqs_degrade_with_phone_commands(self):
        os.unlink(self.root / "tools" / "armcc" / "4.1" / "b1049" / "bin" / "armcc.exe")
        (self.root / "code.bin").unlink(missing_ok=True)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_try_compile(0x100010, str(self.nnsdk), None, False, False)
        self.assertEqual(rc, 2)
        text = buf.getvalue()
        self.assertIn("try-compile needs code.bin", text)
        self.assertIn("git clone https://github.com/3dsdecomp/nnsdk", text)
        self.assertIn("d50a4b89d13c929d2438abf92e5a48f039efffbf", text)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_try_compile(0x100010, str(self.nnsdk), None, False, True)
        self.assertEqual(rc, 2)
        out = json.loads(buf.getvalue())
        self.assertIn("code.bin", out["missing"])
        self.assertIn("armcc", " ".join(out["missing"]))

    def test_no_suggestions_and_bad_addr_degrade(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_try_compile(0x100000, str(self.nnsdk), None, False, True)
        self.assertEqual(rc, 2)  # not in plan state -> no suggestions
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sdkmap.cmd_try_compile(0x100004, str(self.nnsdk), None, False, False)
        self.assertEqual(rc, 2)  # not a start

    def test_dry_run_prints_commands_and_never_registers(self):
        before = (self.root / "functions.json").read_text()
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_try_compile(0x100010, str(self.nnsdk), None, False, False)
        self.assertEqual(rc, 0)
        text = buf.getvalue()
        self.assertIn("fn.py check", text)
        self.assertIn("worklist.py register 0x00100010", text)
        self.assertIn("sdk:nnsdk Include/nn/math/math_VEC3.h", text)
        self.assertEqual((self.root / "functions.json").read_text(), before)
        attempts = [json.loads(l) for l in
                    (self.state / "attempts.jsonl").read_text().splitlines()]
        self.assertEqual(attempts[0]["mode"], "dry-run")
        # the build unit is self-contained under logs/sdkmap/build/
        unit = self.state / "build" / "00100010" / "unit.cpp"
        self.assertTrue(unit.exists())
        text = unit.read_text()
        self.assertTrue(text.startswith("#define NON_MATCHING\n"))
        self.assertIn('#include "%s"' % os.path.abspath(
            unit.parent / "Include__nn__math__math_VEC3.h"), text)
        self.assertTrue((self.state / "build" / "00100010" / "nn").is_dir())

    def test_dry_run_json_and_manual_source(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = sdkmap.cmd_try_compile(0x100010, str(self.nnsdk), "VEC3",
                                        False, True, ["Source/math/math_VEC3.cpp"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["sources"], ["Source/math/math_VEC3.cpp"])
        self.assertEqual(out["note"], "sdk:nnsdk Source/math/math_VEC3.cpp@unknown")
        self.assertTrue(out["dry_run"])

    def test_build_unit_rewrites_angle_includes(self):
        (self.nnsdk / "Source" / "x.cpp").write_text(
            '#include <nn/math/math_VEC3.h>\nnamespace nn { void X(); }\n')
        unit_dir, unit_path = sdkmap.build_unit(0x100010, str(self.nnsdk),
                                                ["Source/x.cpp"])
        copied = (Path(unit_dir) / "Source__x.cpp").read_text()
        # includes resolve to absolute paths inside the unit, so the unit
        # compiles under fn.py check's fixed -I regardless of nesting depth
        self.assertIn('#include "%s"' % os.path.abspath(
            os.path.join(unit_dir, "nn", "math", "math_VEC3.h")), copied)
        self.assertNotIn("<nn/", copied)
        self.assertTrue((Path(unit_dir) / "nn" / "math" / "math_VEC3.h").exists())

    def test_add_sdk_note_follows_note_convention(self):
        functions = self.root / "functions.json"
        data = json.loads(functions.read_text())
        data["00100000"] = {"status": "honest", "path": "src/a.c", "cc": "4.1/b1049",
                            "hack_reasons": []}
        functions.write_text(audit.canonical_bytes(data))
        sdkmap.add_sdk_note("00100000", "sdk:nnsdk Include/nn/Result.h@abc123")
        ent = json.loads(functions.read_text())["00100000"]
        self.assertEqual(ent["note"], "sdk:nnsdk Include/nn/Result.h@abc123")
        self.assertEqual(ent["status"], "honest")
        with self.assertRaises(ValueError):
            sdkmap.add_sdk_note("00100020", "sdk:nnsdk x@y")  # not a matched entry


class SdkNoteAuditTests(unittest.TestCase):
    """A matched entry carrying a sdk:nnsdk note must stay audit-CLEAN: the
    note field is free text (source_lost convention), so no audit invariant
    is added or changed."""

    def test_honest_entry_with_sdk_note_passes_audit(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "funcs.json").write_text(
            json.dumps({"starts": [0x100000, 0x100010], "bl": [], "ptr": []}))
        src = root / "src" / "work8" / "auto" / "func_00100000.c"
        src.parent.mkdir(parents=True)
        src.write_text("u32 func_00100000(u32 r0) { return r0; }\n")
        functions = root / "functions.json"
        data = {"00100000": {"status": "honest", "path": "src/work8/auto/func_00100000.c",
                             "cc": "4.1/b1049", "hack_reasons": [],
                             "note": "sdk:nnsdk Include/nn/Result.h@d50a4b8"}}
        functions.write_text(audit.canonical_bytes(data))

        class FakeGit:
            def run(self, *a, **kw):
                class R:
                    stdout = "src/work8/auto/func_00100000.c\n"
                return R()

        with patch.object(audit, "ROOT", str(root)), \
                patch.object(audit, "TEXT_SIZE", 0x20), \
                patch.object(audit, "subprocess", FakeGit()), \
                patch.object(audit, "load", lambda: json.loads(functions.read_text())):
            _d, errors, _w, n_honest = audit.check_all()
            stats = audit.stats(json.loads(functions.read_text()))
        self.assertEqual(errors, [])
        self.assertEqual(n_honest, 1)
        self.assertEqual(stats["matched_source_included"], 1)


class StatusReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "logs" / "sdkmap"
        self.state.mkdir(parents=True)
        self.inv = make_inventory()
        (self.root / "inv.json").write_text(json.dumps(self.inv))
        (self.state / "plan.json").write_text(json.dumps({"candidates": [
            {"addr": "00100010", "size": 16, "pool": "excluded_library", "score": 100.0,
             "difficulty": "low", "reasons": ["r"], "suggested": ["a.h"]}]}))
        (self.state / "fingerprints.json").write_text(json.dumps(
            {"00100010": {"token_hash": "abc", "n_blocks": 2, "pool_size": 1}}))
        (self.state / "attempts.jsonl").write_text(
            json.dumps({"addr": "00100010", "mode": "dry-run"}) + "\n" +
            json.dumps({"addr": "00100010", "mode": "run", "match": True}) + "\n")
        patchers = [
            patch.object(sdkmap, "ROOT", str(self.root)),
            patch.object(sdkmap, "STATE", str(self.state)),
            patch.object(sdkmap, "PLAN_FILE", str(self.state / "plan.json")),
            patch.object(sdkmap, "FINGER_FILE", str(self.state / "fingerprints.json")),
            patch.object(sdkmap, "ATTEMPTS_FILE", str(self.state / "attempts.jsonl")),
            patch.object(sdkmap, "INVENTORY", str(self.root / "inv.json")),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_status_and_report_offline(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(sdkmap.cmd_status(as_json=True), 0)
        st = json.loads(buf.getvalue())
        self.assertEqual(st["inventory"]["functions"], self.inv["counts"]["functions"])
        self.assertEqual(st["plan"]["candidates"], 1)
        self.assertEqual(st["fingerprints"], 1)
        self.assertEqual(st["try_compile_attempts"], 2)
        self.assertEqual(st["try_compile_matches"], 1)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(sdkmap.cmd_report(as_json=True), 0)
        rep = json.loads(buf.getvalue())
        self.assertEqual(rep["candidates"], 1)
        self.assertTrue(rep["rows"][0]["fingerprinted"])
        self.assertEqual(rep["rows"][0]["token_hash"], "abc")
        self.assertEqual(rep["rows"][0]["n_blocks"], 2)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(sdkmap.cmd_status(as_json=False), 0)
        self.assertIn("sdkmap status", buf.getvalue())

    def test_status_with_empty_state(self):
        for f in ("plan.json", "fingerprints.json", "attempts.jsonl"):
            (self.state / f).unlink()
        (self.root / "inv.json").unlink()
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(sdkmap.cmd_status(as_json=True), 0)
        st = json.loads(buf.getvalue())
        self.assertIsNone(st["inventory"])
        self.assertEqual(st["plan"]["candidates"], 0)


class CliSmokeTests(unittest.TestCase):
    """Read-only CLI smoke tests that also run in stdlib-only CI."""

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "tools/sdkmap.py", *args],
                              capture_output=True, text=True, cwd=ROOT)

    def test_status_json_exits_zero(self):
        r = self.run_cli("status", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        json.loads(r.stdout)

    def test_fingerprint_degrades_with_exit_2(self):
        r = self.run_cli("fingerprint", "--addr", "0x100000", "--json")
        self.assertEqual(r.returncode, 2)
        out = json.loads(r.stdout)
        self.assertTrue(out["missing"])
        self.assertIn("phone_commands", out)

    def test_plan_json_runs_offline_against_repo_metadata(self):
        r = self.run_cli("plan", "--limit", "10", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertGreater(out["n_candidates"], 0)


if __name__ == "__main__":
    unittest.main()
