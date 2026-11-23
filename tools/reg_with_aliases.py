#!/usr/bin/env python
"""Register already-checked sources via worklist, with shared/aliases.json
present during the register call (worklist.register re-runs fn.py check
internally, and the alias-dependent relocs only resolve with the file present).

Usage: python tools/reg_with_aliases.py <ADDR> <SRC> <CTOR_ADDR> [<ADDR> <SRC> <CTOR_ADDR> ...]
Each triple: address hex, source path, ctor target hex (for _ZN1SC1EPv alias).
Writes/removes shared/aliases.json around each register call.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AL = os.path.join(ROOT, "shared", "aliases.json")


def one(addr, src, ctor):
    with open(AL, "w") as fh:
        json.dump({"_Znwj": "0x0010BAB4", "_ZN1SC1EPv": "0x" + ctor}, fh, indent=1)
    r = subprocess.run([sys.executable, "tools/worklist.py", "register", addr, "--src", src],
                       cwd=ROOT, capture_output=True, text=True)
    os.remove(AL)
    out = r.stdout + r.stderr
    ok = "MATCH" in out and "refused" not in out and "Error" not in out.split("MATCH")[0][-200:]
    line = [l for l in out.splitlines() if "RESULT" in l or "refused" in l or "MATCH" in l]
    print(addr, (line[-1] if line else out[-120:]).strip(), flush=True)
    return "refused" not in out and r.returncode == 0


if __name__ == "__main__":
    args = sys.argv[1:]
    n = 0
    for i in range(0, len(args), 3):
        if one(args[i], args[i + 1], args[i + 2]):
            n += 1
    print("registered", n, "of", len(args) // 3)
