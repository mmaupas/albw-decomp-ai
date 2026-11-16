#!/usr/bin/env python
"""Batch-register ops-twins of the 24B vtable-store dtor family
   (honest twin: src/work5/lead/dtors/func_00123DB0.cpp, but that one uses a
   different store order). The 0058EBxx twins use:
     ldr r1,=VT; add r2,r1,#OFF; str r2,[r0],#-0x38; str r1,[r0]; b func_TAIL
   i.e. store secondary vptr at [r0] then post-decrement, store primary at
   [r0-0x38]... actually str r2,[r0],#-0x38 means r0 -= 0x38 AFTER store.
   Order: r2 stored at [r0], r0 -= 0x38, r1 stored at [r0]. Then tail-b.

Per twin: VT (ro_ pool label), OFF (add imm), TAIL (b target).

Usage: python tools/gen_vt_dtor.py <ADDR> [<ADDR>...]
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

TEMPLATE = """typedef unsigned int u32; typedef unsigned char u8;
extern u8 ro_%(VT)s[];
extern "C" void func_%(TAIL)s(void*);
void func_%(ADDR)s(void* self) {
    char* p = (char*)self;
    const void* vt = ro_%(VT)s;
    *(const void**)p = (const char*)vt + %(OFF)d;
    p -= 0x38;
    *(const void**)p = vt;
    func_%(TAIL)s(p);
}
"""


def target_params(addr):
    out = subprocess.run([sys.executable, "tools/fn.py", "show", "0x%08X" % addr],
                         capture_output=True, text=True, cwd=ROOT).stdout
    vt = re.search(r"=0x([0-9a-f]{6,8}) ro_", out).group(1)
    off = re.search(r"add\s+r2, r1, #0x([0-9a-f]+)", out).group(1)
    tail = re.search(r"b\s+#0x([0-9a-f]+)", out).group(1)
    return {"ADDR": "%08X" % addr, "VT": "%08X" % int(vt, 16),
            "OFF": int(off, 16), "TAIL": "%08X" % int(tail, 16)}


def one(addr_hex):
    addr = int(addr_hex, 16)
    p = target_params(addr)
    src = TEMPLATE % p
    tmp = "/storage/emulated/0/vd_%s.cpp" % p["ADDR"]
    with open(tmp, "w") as fh:
        fh.write(src)
    r = subprocess.run([sys.executable, "tools/fn.py", "check", tmp, "0x%08X" % addr],
                       cwd=ROOT, capture_output=True, text=True)
    line = [l for l in r.stdout.splitlines() if "RESULT" in l]
    ok = bool(line) and "MATCH" in line[0] and "NO MATCH" not in line[0]
    print(p["ADDR"], line[0] if line else "?", p, flush=True)
    if ok:
        subprocess.run([sys.executable, "tools/worklist.py", "register", p["ADDR"],
                        "--src", tmp], cwd=ROOT, capture_output=True)
        print(p["ADDR"], "registered", flush=True)
    return ok


if __name__ == "__main__":
    for a in sys.argv[1:]:
        one(a)
