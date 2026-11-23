#!/usr/bin/env python
"""Batch-register ops-twins of the `new(size); if(p) tail-b ctor` family
   (honest twin: src/work7/gpt21/func_00602770.cpp).

Uses the exact honest shape (operator new(u32) decl + `new S(value)`) which
armcc compiles to the target sequence ONLY when aliases map _Znwj -> 0x0010BAB4
and the S-ctor mangled name -> the real ctor address. Per-target: SIZE from the
pool word, CTOR from the tail-b target. Aliases written to shared/aliases.json
for the duration of each check, removed after.

Usage: python tools/gen_new_tail.py <ADDR> [<ADDR>...]
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
AL = os.path.join(ROOT, "shared", "aliases.json")

TEMPLATE = """typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[%(SIZE)d]; S(void*); };
S* func_%(ADDR)s(void* value) { return new S(value); }
"""


def target_params(addr):
    out = subprocess.run([sys.executable, "tools/fn.py", "show", "0x%08X" % addr],
                         capture_output=True, text=True, cwd=ROOT).stdout
    size = int(re.search(r"\.word\s+0x([0-9a-f]+)", out).group(1), 16)
    tail = re.search(r"b\s+#0x([0-9a-f]+)", out[out.find("pop      {r4, lr}"):]).group(1)
    return {"ADDR": "%08X" % addr, "SIZE": size, "CTOR": "%08X" % int(tail, 16)}


def one(addr_hex):
    addr = int(addr_hex, 16)
    p = target_params(addr)
    src = TEMPLATE % p
    tmp = "/storage/emulated/0/nt_%s.cpp" % p["ADDR"]
    with open(tmp, "w") as fh:
        fh.write(src)
    with open(AL, "w") as fh:
        json.dump({"_Znwj": "0x0010BAB4", "_ZN1SC1EPv": "0x" + p["CTOR"]}, fh, indent=1)
    r = subprocess.run([sys.executable, "tools/fn.py", "check", tmp, "0x%08X" % addr],
                       cwd=ROOT, capture_output=True, text=True)
    os.remove(AL)
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
