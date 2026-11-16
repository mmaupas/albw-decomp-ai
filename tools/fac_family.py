#!/usr/bin/env python
"""Batch-register the 00602CA4 factory-mk ops-twin family.

For each twin ADDR: generate source via gen_fac_twin.gen(), write per-target
shared/aliases.json, fn.py check (must be MATCH), then worklist.py register.
Run one addr at a time (armcc lock; --jobs 1). Usage: python tools/fac_family.py <ADDR>
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import gen_fac_twin as g

AL = os.path.join(ROOT, "shared", "aliases.json")


def one(addr_hex):
    addr = int(addr_hex, 16)
    src, aliases, lbl = g.gen(addr)
    tmp = "/storage/emulated/0/fac_%s.cpp" % lbl["addr"]
    with open(tmp, "w") as fh:
        fh.write(src)
    with open(AL, "w") as fh:
        json.dump(aliases, fh, indent=1)
    r = subprocess.run([sys.executable, "tools/fn.py", "check", tmp, "0x%08X" % addr],
                       cwd=ROOT, capture_output=True, text=True)
    line = [l for l in r.stdout.splitlines() if "RESULT" in l]
    ok = bool(line) and "MATCH" in line[0] and "NO MATCH" not in line[0]
    print(lbl["addr"], line[0] if line else "?", flush=True)
    if ok:
        subprocess.run([sys.executable, "tools/worklist.py", "register", lbl["addr"],
                        "--src", tmp], cwd=ROOT, capture_output=True)
        print(lbl["addr"], "registered", flush=True)
    os.remove(AL)
    return ok


if __name__ == "__main__":
    for a in sys.argv[1:]:
        one(a)
