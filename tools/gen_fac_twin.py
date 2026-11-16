#!/usr/bin/env python
"""Generate per-target ops-twin sources + aliases for the 00602CA4 factory-mk family.

Proven mechanism (see logs): gen_fac3_all.cpp matches 00602CA4 at 25/25 ONLY with
shared/aliases.json mapping its constant mangled names to the real call targets:
  _Znwj7NoThrow -> 0x0010BAB4
  _ZN7P602CA4C1EjjPKvi -> 0x00339CC4
  _Z7X602CA4PvPKv -> 0x004C03B8
  GD602CA4 -> <target data_ label>, GE602CA4 -> <target bss_ label>
Per target, only the pool labels and the P-ctor arg b differ, so:
  1. copy gen_fac3_all.cpp's first factory block
  2. sed the ro_ label to the target's (address labels auto-resolve, no alias needed)
  3. sed b=3 -> b=<target b> if different
  4. write shared/aliases.json with per-target GD/GE
  5. fn.py check; on MATCH, register with the source renamed func_<ADDR>

Usage:  python tools/gen_fac_twin.py <ADDR> [--check] [--register]
"""
import json
import re
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
SRC = os.path.join(ROOT, "src", "work7", "ds7", "gen_fac3_all.cpp")
AL = os.path.join(ROOT, "shared", "aliases.json")


def target_labels(addr):
    out = subprocess.run([sys.executable, "tools/fn.py", "show", "0x%08X" % addr],
                         capture_output=True, text=True, cwd=ROOT).stdout
    gd = re.search(r"=0x([0-9a-f]{6,8}) data_", out)
    vt = re.search(r"=0x([0-9a-f]{6,8}) ro_", out)
    bss = re.search(r"=0x([0-9a-f]{6,8}) bss_", out)
    b = re.search(r"mov\s+r2, #(\d+)", out)
    return {"addr": "%08X" % addr,
            "GD": gd.group(1).upper() if gd else "000000",
            "VT": vt.group(1).upper() if vt else "000000",
            "BSS": bss.group(1).upper() if bss else "000000",
            "b": int(b.group(1)) if b else 4}


def gen(addr):
    lbl = target_labels(addr)
    src = open(SRC).read()
    cut = src.find("extern u8 GD602DA4")
    if cut > 0:
        src = src[:cut]
    # inline range.h's needed decls so the try file is self-contained
    src = src.replace('#include "range.h"',
                      'typedef unsigned int u32; typedef int s32; typedef unsigned char u8;\n'
                      'struct NoThrow {};\n'
                      'void* operator new(unsigned int, NoThrow);\n'
                      'inline void* operator new(unsigned int, void* p) { return p; }')
    src = src.replace("ro_006C6F50", "ro_%s" % lbl["VT"])
    src = src.replace("P602CA4(a, 3, GD602CA4, -1)",
                      "P602CA4(a, %d, GD602CA4, -1)" % lbl["b"])
    src = src.replace("v602CA4", "func_%s" % lbl["addr"])
    aliases = {"_Znwj7NoThrow": "0x0010BAB4",
               "_ZN7P602CA4C1EjjPKvi": "0x00339CC4",
               "_Z7X602CA4PvPKv": "0x004C03B8",
               "GD602CA4": "0x00" + lbl["GD"],
               "GE602CA4": "0x00" + lbl["BSS"]}
    return src, aliases, lbl


if __name__ == "__main__":
    addr = int(sys.argv[1], 16)
    src, aliases, lbl = gen(addr)
    dest = os.path.join(ROOT, "src", "work8", "auto", "func_%s_try.cpp" % lbl["addr"])
    with open(dest, "w") as fh:
        fh.write(src)
    with open(AL, "w") as fh:
        json.dump(aliases, fh, indent=1)
    print("wrote", dest, lbl)
    if "--check" in sys.argv or "--register" in sys.argv:
        r = subprocess.run([sys.executable, "tools/fn.py", "check", dest, "0x%08X" % addr],
                           cwd=ROOT, capture_output=True, text=True)
        line = [l for l in r.stdout.splitlines() if "RESULT" in l]
        print(line[0] if line else r.stdout[-200:])
        if "--register" in sys.argv and line and "MATCH" in line[0] and "NO MATCH" not in line[0]:
            os.remove(AL)
            os.rename(dest, os.path.join(ROOT, "src", "work8", "auto", "func_%s.cpp" % lbl["addr"]))
            subprocess.run([sys.executable, "tools/worklist.py", "register", lbl["addr"],
                            "--src", os.path.join(ROOT, "src", "work8", "auto", "func_%s.cpp" % lbl["addr"])],
                           cwd=ROOT)
        else:
            os.remove(AL)
