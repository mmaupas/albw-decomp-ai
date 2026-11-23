#!/usr/bin/env python
"""Batch-register ops-twins of the `mov r0,#SIZE; bl new; if(p){bl ctor; store
   vtable(+off) at [r] and [r,#0x320]; } return` family — variant with SIZE as
   mov-immediate (not pool word), like honest 0060298C (gen_vtfac_all.cpp).

Same mechanism as gen_new_vt.py but size comes from `mov r0, #IMM`.

Usage: python tools/gen_new_vt2.py <ADDR> [<ADDR>...]
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

TEMPLATE = """typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_%(CTOR)s(void*, u32);
extern u8 ro_%(VT)s[];
void* func_%(ADDR)s(u32 a0) {
    void* p = func_0010BAB4(%(SIZE)d);
    if (!p) return 0;
    void* r = func_%(CTOR)s(p, a0);
    const void* vt = ro_%(VT)s;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + %(OFF)d;
    return r;
}
"""


def target_params(addr):
    out = subprocess.run([sys.executable, "tools/fn.py", "show", "0x%08X" % addr],
                         capture_output=True, text=True, cwd=ROOT).stdout
    size = int(re.search(r"mov\s+r0, #0x([0-9a-f]+)", out).group(1), 16)
    ctor = re.search(r"bl\s+#0x([0-9a-f]+)", out[out.find("mov      r1, r4"):]).group(1)
    vt = re.search(r"=0x([0-9a-f]{6,8}) ro_", out).group(1)
    off = re.search(r"add\s+r2, r1, #0x([0-9a-f]+)", out).group(1)
    return {"ADDR": "%08X" % addr, "SIZE": size, "CTOR": "%08X" % int(ctor, 16),
            "VT": "%08X" % int(vt, 16), "OFF": int(off, 16)}


def one(addr_hex):
    addr = int(addr_hex, 16)
    p = target_params(addr)
    src = TEMPLATE % p
    tmp = "/storage/emulated/0/nv2_%s.cpp" % p["ADDR"]
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
