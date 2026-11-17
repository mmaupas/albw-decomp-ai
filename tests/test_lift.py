import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import lift


def asm(*words):
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)


def mov_imm(rd, imm):
    return 0xE3A00000 | (rd << 12) | (imm & 0xFFF)


def build_fixture():
    """Synthetic ARM image (no game content): five tiny functions.

    F0  register-only leaf (round-trip executable on a host cc):
        mov r4, r0; add r0, r0, #7; cmp r0, #10; movlt r0, #0;
        lsl r0, r0, #1; sub r0, r0, r4; bx lr
    F1  stack frame + call: push {r4, lr}; mov r4, r0; bl F0; add r0, r0, r4;
        pop {r4, pc}
    F2  switch: b L; ldr pc, [pc, r0, lsl #2]; <3 table words>; L: mov r0,#1;
        bx lr; mov r0,#2; bx lr; mov r0,#3; bx lr
    F3  helper call: mov r0,#5; mov r1,#3; bl <non-start>; bx lr
    F4  unsupported: mcr p15,...; bx lr
    F5  tail call: b F0
    """
    TA = 0x100000
    f0 = asm(mov_imm(4, 0), 0xE1A04000, 0xE2800007, 0xE350000A, 0xB3A00000,
             0xE1A00081, 0xE0400004, 0xE12FFF1E)
    f0_addr = TA
    f1_addr = f0_addr + len(f0)
    f1 = asm(0xE92D4010, 0xE1A04000, 0xEB000000, 0xE0800004, 0xE8BD8010)
    # patch bl in f1 to target f0
    bl_off = (f0_addr - (f1_addr + 8 + 8)) >> 2
    f1 = f1[:8] + asm(0xEB000000 | (bl_off & 0xFFFFFF)) + f1[12:]  # bl is the 3rd word
    f2_addr = f1_addr + len(f1)
    # f2: b case0; ldr pc,[pc,r0,lsl#2] at f2+4 (table at f2+12); cases at f2+24..
    case0 = f2_addr + 24
    b_word = 0xEA000000 | (((case0 - (f2_addr + 8)) >> 2) & 0xFFFFFF)
    table = [case0, case0 + 4, case0 + 8]
    f2 = asm(b_word, 0xE79FF100, 0xE1A00000) + asm(*table) + asm(
        mov_imm(0, 1), 0xE12FFF1E, mov_imm(0, 2), 0xE12FFF1E, mov_imm(0, 3), 0xE12FFF1E)
    f3_addr = f2_addr + len(f2)
    helper = 0x200000  # not a start: __aeabi-style helper
    bl_helper = 0xEB000000 | (((helper - (f3_addr + 8 + 8)) >> 2) & 0xFFFFFF)
    f3 = asm(mov_imm(0, 5), mov_imm(1, 3), bl_helper, 0xE12FFF1E)
    f4_addr = f3_addr + len(f3)
    f4 = asm(0xEE070F9A, 0xE12FFF1E)  # mcr p15, #0, r0, c7, c10, #4
    f5_addr = f4_addr + len(f4)
    b_tail = 0xEA000000 | (((f0_addr - (f5_addr + 8)) >> 2) & 0xFFFFFF)
    f5 = asm(b_tail)
    data = f0 + f1 + f2 + f3 + f4 + f5
    starts = [f0_addr, f1_addr, f2_addr, f3_addr, f4_addr, f5_addr]
    return lift.Image(data, TA), starts


# ------------------------------------------------- tiny ARM interpreter

def interpret(img, starts, addr, r0=0, r1=0, r2=0, r3=0, max_steps=1000):
    """Interpret the fixture's instruction subset; returns (r0, r1, ...)."""
    regs = [r0, r1, r2, r3] + [0] * 9 + [0, 0]  # r0-r12, sp, lr
    f = [0, 0, 0, 0]  # N Z C V
    end = min(starts[-1] + 64, img.ta + len(img.data))

    def cond_ok(cond):
        N, Z, C, V = f
        return {"al": True, "eq": Z, "ne": not Z, "lt": N != V, "ge": N == V,
                "cs": C, "cc": not C, "mi": N, "pl": not N}[cond]

    steps = 0
    pc = addr
    while steps < max_steps:
        steps += 1
        w = img.word(pc)
        cond = {0x0: "eq", 0x1: "ne", 0x4: "cc", 0x5: "lt", 0xA: "ge", 0xB: "lt",
                0xE: "al", 0xF: "al"}.get(w >> 28, "al")
        top = w & 0x0FFFFFFF
        if cond != "al" and not cond_ok(cond):
            pc += 4
            continue
        if (w & 0x0FF00000) == 0x03A00000:  # mov imm
            regs[(w >> 12) & 0xF] = w & 0xFFF
        elif (w & 0x0FE00010) == 0x01A00000:  # mov reg / reg-shift (lsl/lsr/asr/ror #n)
            rd, rm = (w >> 12) & 0xF, w & 0xF
            stype, simm = (w >> 5) & 0x3, (w >> 7) & 0x1F
            v = regs[rm]
            if stype == 0 and simm:
                v = (v << simm) & 0xFFFFFFFF
            elif stype == 1:
                v = v >> (simm or 32)
            elif stype == 2:  # asr
                sv = regs[rm] - 0x100000000 if regs[rm] >> 31 else regs[rm]
                v = (sv >> min(simm, 32)) & 0xFFFFFFFF
            elif stype == 3:
                n = simm % 32
                v = ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF if n else v
            else:
                v = regs[rm]
            regs[rd] = v & 0xFFFFFFFF
        elif (w & 0x0FE00000) == 0x02800000:  # add imm
            rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
            a, b = regs[rn], w & 0xFFF
            r = (a + b) & 0xFFFFFFFF
            f[0], f[1] = r >> 31, int(r == 0)
            f[2] = int(a + b > 0xFFFFFFFF)
            f[3] = ((~(a ^ b) & (a ^ r)) >> 31) & 1
            regs[rd] = r
        elif (w & 0x0FE000F0) == 0x00400010 or (w & 0x0FE000F0) == 0x00400000:  # sub reg
            rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
            a, b = regs[rn], regs[w & 0xF]
            r = (a - b) & 0xFFFFFFFF
            f[0], f[1] = r >> 31, int(r == 0)
            f[2] = int(a >= b)
            f[3] = (((a ^ b) & (a ^ r)) >> 31) & 1
            regs[rd] = r
        elif (w & 0x0FF00000) == 0x03500000:  # cmp imm
            a, b = regs[(w >> 16) & 0xF], w & 0xFFF
            r = (a - b) & 0xFFFFFFFF
            f[0], f[1] = r >> 31, int(r == 0)
            f[2] = int(a >= b)
            f[3] = (((a ^ b) & (a ^ r)) >> 31) & 1
        elif (w & 0x0FFFFFF0) == 0x012FFF10:  # bx reg
            if (w & 0xF) == 14:
                return regs[0]
            pc = regs[w & 0xF]
            continue
        elif (w & 0x0F000000) == 0x0A000000:  # b
            imm = w & 0xFFFFFF
            imm = imm - 0x1000000 if imm & 0x800000 else imm
            pc = pc + 8 + (imm << 2)
            continue
        elif (w & 0x0F000000) == 0x0B000000:  # bl
            imm = w & 0xFFFFFF
            imm = imm - 0x1000000 if imm & 0x800000 else imm
            regs[14] = pc + 4
            pc = pc + 8 + (imm << 2)
            continue
        elif (w & 0x0FFFFFF0) == 0x079FF100:  # ldr pc, [pc, rX, lsl #2]
            idx = regs[(w >> 16) & 0xF]
            pc = img.word(pc + 8 + idx * 4)
            continue
        elif (w & 0xFFFF0000) == 0xE92D0000:  # push (stmdb sp!)
            lst = w & 0xFFFF
            for i in range(15):
                if lst & (1 << i):
                    regs[13] = (regs[13] - 4) & 0xFFFFFFFF
                    img_store(img, regs[13], regs[i])
        elif (w & 0xFFFF0000) == 0xE8BD0000:  # pop (ldmia sp!)
            lst = w & 0xFFFF
            for i in range(15):
                if lst & (1 << i):
                    regs[i] = img_load(img, regs[13])
                    regs[13] = (regs[13] + 4) & 0xFFFFFFFF
                    if i == 15:
                        return regs[0]
        elif (w & 0x0F900000) == 0x05800000:  # str imm
            rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
            off = w & 0xFFF
            if not ((w >> 23) & 1):
                off = -off
            img_store(img, (regs[rn] + off) & 0xFFFFFFFF, regs[rd])
        elif (w & 0x0F900000) == 0x05900000:  # ldr imm
            rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
            off = w & 0xFFF
            if not ((w >> 23) & 1):
                off = -off
            regs[rd] = img_load(img, (regs[rn] + off) & 0xFFFFFFFF)
        else:
            raise AssertionError("interpreter: unhandled word %08X at %08X" % (w, pc))
        pc += 4
    raise AssertionError("interpreter: step limit")


_STACK = {}


def img_store(img, addr, value):
    _STACK[addr & 0xFFFFFFF] = value & 0xFFFFFFFF


def img_load(img, addr):
    return _STACK.get(addr & 0xFFFFFFF, 0)


# The offline CI workflow runs stdlib-only (no capstone); every test that
# actually disassembles is skipped there and runs under `uv run` (uv sync).
needs_capstone = unittest.skipIf(lift.Cs is None,
                                 "capstone not installed (uv sync); stdlib-only runs skip this")


@needs_capstone
class LiftCoreTests(unittest.TestCase):
    def setUp(self):
        self.img, self.starts = build_fixture()

    def test_banner_externs_and_frame(self):
        r = lift.lift_function(self.img, self.starts, self.starts[1])  # F1: push/bl/pop
        self.assertIsNone(r["unsupported"])
        self.assertIn("LIFTED: semantic scaffold, not byte-exact. Do not register as matched.", r["text"])
        self.assertIn("Generated by tools/lift.py from %08X." % self.starts[1], r["text"])
        self.assertIn("extern u32 func_%08X(u32, u32, u32, u32);" % self.starts[0], r["text"])
        self.assertIn("LIFT_ST32(sp, r4);", r["text"])
        self.assertIn("r0 = func_%08X(r0, r1, r2, r3);" % self.starts[0], r["text"])
        self.assertIn("u8 stack[", r["text"])
        self.assertIn("return r0;", r["text"])

    def test_conditional_and_alu_flags(self):
        r = lift.lift_function(self.img, self.starts, self.starts[0])  # F0
        self.assertIn("if ((fN != fV)) {", r["text"])  # movlt
        self.assertIn("r0 = (r0 + 0x7u);", r["text"])
        self.assertIn("r0 = ((u32)(r1) << 1);", r["text"])  # lsl r0, r1, #1
        self.assertIn("r0 = (r0 - r4);", r["text"])

    def test_jump_table_becomes_switch(self):
        r = lift.lift_function(self.img, self.starts, self.starts[2])  # F2
        self.assertIsNone(r["unsupported"])
        self.assertIn("switch (r0) {", r["text"])
        self.assertEqual(r["text"].count("case "), 3)
        self.assertIn("default: return 0;", r["text"])

    def test_helper_call_is_opaque_extern_with_warning(self):
        r = lift.lift_function(self.img, self.starts, self.starts[3])  # F3
        self.assertIn("extern u32 lift_helper_00200000(u32, u32, u32, u32);", r["text"])
        self.assertTrue(any("__aeabi_*" in w for w in r["warnings"]))

    def test_unsupported_construct_makes_marked_stub(self):
        r = lift.lift_function(self.img, self.starts, self.starts[4])  # F4: mcr
        self.assertIsNotNone(r["unsupported"])
        self.assertIn("/* LIFT-UNSUPPORTED: instruction mcr", r["text"])
        self.assertIn("return 0;", r["text"])
        self.assertIn("LIFTED:", r["text"])  # banner still present

    def test_tail_call_to_start_is_plain_call(self):
        r = lift.lift_function(self.img, self.starts, self.starts[5])  # F5: b F0
        self.assertIn("extern u32 func_%08X(u32, u32, u32, u32);" % self.starts[0], r["text"])
        self.assertIn("return func_%08X(r0, r1, r2, r3);" % self.starts[0], r["text"])

    def test_tokens_reuse_shapemine_vocabulary(self):
        r = lift.lift_function(self.img, self.starts, self.starts[1])  # F1 has bl
        self.assertGreaterEqual(r["n_call"], 1)
        import shapemine
        self.assertIn("bl CALL", r["tokens"])
        self.assertTrue(all(isinstance(t, str) for t in r["tokens"]))

    def test_non_start_address_is_rejected(self):
        with self.assertRaises(ValueError):
            lift.lift_function(self.img, self.starts, self.starts[0] + 4)

    def test_roundtrip_fixture_bytes_to_c_to_behavior(self):
        """Assemble fixture words -> lift to C -> compile with host cc -> run;
        compare against a direct interpretation of the same fixture bytes."""
        cc = shutil.which("cc") or shutil.which("gcc")
        if not cc:
            self.skipTest("no host C compiler")
        r = lift.lift_function(self.img, self.starts, self.starts[0])  # F0: register-only
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "lifted.c"
            src.write_text(r["text"])
            main = Path(tmp) / "main.c"
            main.write_text('#include <stdio.h>\n#include <stdlib.h>\n'
                            'typedef unsigned int u32;\n'
                            'u32 func_%08X(u32, u32, u32, u32);\n'
                            'int main(int argc, char **argv) {\n'
                            '  printf("%%u\\n", func_%08X((u32)strtoul(argv[1], 0, 0), 0, 0, 0));\n'
                            '  return 0;\n}\n' % (self.starts[0], self.starts[0]))
            exe = Path(tmp) / "prog"
            include = str(Path(__file__).resolve().parents[1] / "shared" / "include")
            res = subprocess.run([cc, "-O0", "-w", "-I", include, "-o", str(exe),
                                  str(src), str(main)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            for arg in ("0", "3", "5", "20", "100", "4294967295"):
                out = subprocess.run([str(exe), arg], capture_output=True, text=True, check=True)
                got = int(out.stdout.strip())
                want = interpret(self.img, self.starts, self.starts[0], r0=int(arg) & 0xFFFFFFFF)
                self.assertEqual(got, want, "arg %s: C says %d, fixture bytes say %d" % (arg, got, want))


class LiftCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.img, self.starts = build_fixture()
        self.image_path = self.root / "fixture.bin"
        self.image_path.write_bytes(self.img.data)
        (self.root / "funcs.json").write_text(json.dumps({"starts": self.starts, "bl": [], "ptr": []}))
        (self.root / "functions.json").write_text(json.dumps({
            "%08X" % self.starts[0]: {"status": "honest", "path": "src/x.c", "cc": "4.1/b1049"},
        }))
        self.state = self.root / "logs" / "lift"
        patchers = [
            patch.object(lift, "ROOT", str(self.root)),
            patch.object(lift, "FUNCS", str(self.root / "funcs.json")),
            patch.object(lift, "FUNCTIONS", str(self.root / "functions.json")),
            patch.object(lift, "STATE", str(self.state)),
            patch.object(lift, "STATE_FILE", str(self.state / "state.json")),
            patch.object(lift, "LOCK", str(self.state / "lift.lock")),
            patch.object(lift, "LIFT_DIR", str(self.root / "src_lifted")),
            patch.object(lift, "CODE_BIN", str(self.root / "code.bin")),
            patch.object(lift, "SYMBOLS", str(self.root / "symbols.jsonl")),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    @needs_capstone
    def test_lift_writes_file_ledger_and_state(self):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = lift.cmd_lift(self.starts[1], image_path=str(self.image_path), as_json=True)
        self.assertEqual(rc, 0)
        out = json.loads(out.getvalue())
        self.assertEqual(out["status"], "lifted")
        path = self.root / "src_lifted" / ("func_%08X.c" % self.starts[1])
        self.assertTrue(path.exists())
        text = path.read_text()
        self.assertIn("LIFTED: semantic scaffold, not byte-exact. Do not register as matched.", text)
        entry = json.loads((self.root / "functions.json").read_text())["%08X" % self.starts[1]]
        self.assertEqual(entry["status"], "lifted")
        self.assertEqual(entry["path"], "src_lifted/func_%08X.c" % self.starts[1])
        state = json.loads((self.state / "state.json").read_text())
        self.assertIn("%08X" % self.starts[1], state["lifted"])

    def test_lift_refuses_existing_matched_entry(self):
        with self.assertRaises(ValueError):
            lift.cmd_lift(self.starts[0], image_path=str(self.image_path))

    def test_lift_requires_exact_start(self):
        with self.assertRaises(ValueError):
            lift.cmd_lift(self.starts[0] + 4, image_path=str(self.image_path))

    def test_missing_image_degrades_to_phone_plan(self):
        rc = lift.cmd_lift(self.starts[1])  # no code.bin, no --image
        self.assertEqual(rc, 2)

    @needs_capstone
    def test_batch_is_budgeted_and_resumable(self):
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()):
            rc = lift.cmd_batch(limit=10, budget=2, filters=["all"], min_size=0,
                                image_path=str(self.image_path), as_json=True)
        self.assertEqual(rc, 0)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            lift.cmd_batch(limit=10, budget=10, filters=["all"], min_size=0,
                           image_path=str(self.image_path), as_json=True)
        second = json.loads(out.getvalue())
        self.assertEqual(second["total_lifted"], 5)  # F1..F5 (F0 is matched)
        self.assertEqual(second["lifted_this_run"], 3)  # the 2 from the first run are skipped
        funcs = json.loads((self.root / "functions.json").read_text())
        self.assertEqual(sum(1 for v in funcs.values() if v["status"] == "lifted"), 5)
        self.assertEqual(funcs["%08X" % self.starts[0]]["status"], "honest")  # untouched

    def test_targets_status_report_offline(self):
        import contextlib, io
        funcs = json.loads((self.root / "functions.json").read_text())
        rows = lift.lift_targets(funcs, self.starts, ("all",))
        # sorted smallest-first; the last start gets TEXT_END-start (consecutive-starts
        # convention), so F5 sorts last: F4 (8B), F3 (16B), F1 (20B), F2 (48B), F5
        self.assertEqual([r["addr"] for r in rows],
                         ["%08X" % s for s in (self.starts[4], self.starts[3],
                                               self.starts[1], self.starts[2], self.starts[5])])
        self.assertTrue(all(r["reason"] == "unmatched" for r in rows))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(lift.cmd_status(as_json=True), 0)
        self.assertEqual(json.loads(out.getvalue())["pending_targets"], 5)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(lift.cmd_report(as_json=True), 0)
        self.assertEqual(json.loads(out.getvalue())["lifted"], 0)


if __name__ == "__main__":
    unittest.main()
