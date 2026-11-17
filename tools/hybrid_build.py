#!/usr/bin/env python
"""Hybrid image builder: matched + lifted + original bytes in one image.

  python tools/hybrid_build.py --check [--json]          offline composition plan (no armcc, no code.bin)
  python tools/hybrid_build.py [--out PATH] [--json]     full build (needs code.bin + armcc, lock, --jobs 1)
  python tools/hybrid_build.py report [--json]           composition stats of the last plan/build

The hybrid image assembles three layers at the original addresses into
build/hybrid.bin (default --out; never code.bin, never an overwrite of
anything else):
  1. byte-exact matched sources (honest, or hack with --include-hacks),
     recompiled with armcc exactly like the image gate does - the
     compile/resolve/place machinery is IMPORTED from rebuild_check.py
     (assemble_image), not forked;
  2. lifted semantic stubs (src_lifted/, status "lifted"), compiled with
     armcc under the same repo lock, serialized (--jobs 1: one armcc call
     per function, never parallel - parallel wine instances OOM the phone);
  3. the original code.bin bytes for everything else.

The output is a TESTING ARTIFACT, not a release artifact: it exists so the
behavioral oracle (worklist.py verify / behavioral_oracle.py) can run the
game with decompiled functions swapped in, long before full matching. It is
never compared for byte-exactness and never published; rebuild_check.py's
image gate is unchanged and still the only byte-exact gate.

code.bin is only ever read through the same SHA-1-verified, read-only path
the gate uses (common.load_binary). --check needs neither code.bin nor
armcc and reports the planned composition (matched/lifted/original bytes
and per-region coverage) computed offline from funcs.json + functions.json.
Without the proprietary inputs the full build degrades to the exact
Termux commands to run later.

State: logs/hybrid/{state.json,plan.json,obj/} (gitignored, resumable -
compiled objects are cached per address under logs/hybrid/obj/, separate
from the gate's logs/rebuild/obj/ so a lifted stub can never be mistaken
for a matched object).
"""
import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (ROOT, TEXT_SIZE, TEXT_START, atomic_write, file_lock,
                    load_binary, read_json, write_json)  # noqa: E402

STATE = os.path.join(ROOT, "logs", "hybrid")
STATE_FILE = os.path.join(STATE, "state.json")
PLAN_FILE = os.path.join(STATE, "plan.json")
OBJDIR = os.path.join(STATE, "obj")
LOCK = os.path.join(ROOT, "logs", "compiler.lock")  # the repo-wide compiler lock (fn.py uses it too)
DEFAULT_OUT = os.path.join(ROOT, "build", "hybrid.bin")
REGION = 0x10000  # 64 KiB per-region coverage buckets

PHONE_HINT = """full hybrid build needs the proprietary inputs, absent in this environment:
  - code.bin in the repo root (user-supplied, SHA-1 e6ab7d66ee62e879248b0660aaf38d22202e604b)
  - tools/armcc/4.1/b1049/bin/armcc.exe (+ wine on Linux/Termux)
On the phone (Termux):
  uv run python tools/lift.py batch --limit 200 --budget 20     # lift stubs first
  uv run python tools/hybrid_build.py --out build/hybrid.bin    # full build under the lock, --jobs 1
  uv run python tools/hybrid_build.py report --json
Offline composition plan (no inputs needed): uv run python tools/hybrid_build.py --check --json"""


# ------------------------------------------------------- offline composition

def composition(functions, starts):
    """Pure offline layer assignment over funcs.json + functions.json.

    Returns per-layer function/byte counts plus per-region coverage.
    Lifted/semantic_match never count as matched bytes.
    """
    layers = {"matched": [0, 0], "lifted": [0, 0], "original": [0, 0]}
    regions = {}
    total = len(starts)
    for i, addr in enumerate(starts):
        end = starts[i + 1] if i + 1 < total else TEXT_START + TEXT_SIZE
        size = end - addr
        ent = functions.get("%08X" % addr) or {}
        status = ent.get("status")
        if status in ("honest", "hack") and ent.get("path"):
            layer = "matched"
        elif status == "lifted" and ent.get("path"):
            layer = "lifted"
        else:
            layer = "original"
        layers[layer][0] += 1
        layers[layer][1] += size
        reg = regions.setdefault(addr // REGION, {"lo": (addr // REGION) * REGION,
                                                   "matched": [0, 0], "lifted": [0, 0], "original": [0, 0]})
        reg[layer][0] += 1
        reg[layer][1] += size
    return {
        "total_functions": total,
        "text_bytes": TEXT_SIZE,
        "layers": {k: {"functions": v[0], "bytes": v[1]} for k, v in layers.items()},
        "regions": [regions[k] for k in sorted(regions)],
    }


def load_state():
    if os.path.exists(STATE_FILE):
        return read_json(STATE_FILE)
    return {"runs": 0, "builds": []}


def save_state(state):
    write_json(STATE_FILE, state)


def cmd_check(as_json=False):
    functions = read_json(os.path.join(ROOT, "functions.json"))
    starts = read_json(os.path.join(ROOT, "funcs.json"))["starts"]
    plan = composition(functions, starts)
    plan["mode"] = "check (offline plan; no armcc, no code.bin)"
    write_json(PLAN_FILE, plan)
    if as_json:
        print(json.dumps(plan))
    else:
        L = plan["layers"]
        print("hybrid composition plan over %d functions / %d .text bytes:" % (plan["total_functions"], plan["text_bytes"]))
        for name in ("matched", "lifted", "original"):
            print("  %-8s %6d functions  %10d bytes  (%5.1f%% of .text)" % (
                name, L[name]["functions"], L[name]["bytes"], 100.0 * L[name]["bytes"] / plan["text_bytes"]))
        covered = L["matched"]["functions"] + L["lifted"]["functions"]
        print("  decompiled coverage (matched+lifted): %d functions (%.1f%%)" % (
            covered, 100.0 * covered / plan["total_functions"]))
        print("per-region coverage (64 KiB buckets, first 12):")
        for reg in plan["regions"][:12]:
            tot = sum(reg[k][1] for k in ("matched", "lifted", "original"))
            print("  %08X-%08X  matched %7d B  lifted %7d B  original %7d B" % (
                reg["lo"], reg["lo"] + REGION, reg["matched"][1], reg["lifted"][1], reg["original"][1]))
        print("NEXT  on the phone: uv run python tools/hybrid_build.py --out build/hybrid.bin  # full build")
    return 0


def cmd_report(as_json=False):
    functions = read_json(os.path.join(ROOT, "functions.json"))
    starts = read_json(os.path.join(ROOT, "funcs.json"))["starts"]
    plan = composition(functions, starts)
    state = load_state()
    out = dict(plan)
    out["mode"] = "report"
    out["runs"] = state.get("runs", 0)
    out["last_build"] = state["builds"][-1] if state.get("builds") else None
    if as_json:
        print(json.dumps(out))
    else:
        L = out["layers"]
        print("hybrid report: matched %d fn/%d B, lifted %d fn/%d B, original %d fn/%d B; %d build(s) run" % (
            L["matched"]["functions"], L["matched"]["bytes"],
            L["lifted"]["functions"], L["lifted"]["bytes"],
            L["original"]["functions"], L["original"]["bytes"], out["runs"]))
        if out["last_build"]:
            b = out["last_build"]
            print("last build: %s (%d/%d functions recompiled, SHA-1 %s)" % (
                b["out"], b["compiled"], b["entries"], b["sha1"]))
        print("NEXT  python tools/hybrid_build.py --check  # offline plan")
    return 0


# ------------------------------------------------------------- full build

def atomic_write_bytes(path, data):
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def cmd_build(out_path, include_hacks=False, limit=None, as_json=False):
    code_bin = os.path.join(ROOT, "code.bin")
    exe = os.path.join(ROOT, "tools", "armcc", "4.1", "b1049", "bin", "armcc.exe")
    if not os.path.exists(code_bin) or not os.path.exists(exe):
        print(PHONE_HINT)
        return 2
    import rebuild_check  # noqa: E402  (imports fn; needs only funcs.json at import time)
    functions = read_json(os.path.join(ROOT, "functions.json"))
    entries = rebuild_check.honest_entries(include_hacks=include_hacks, limit=limit)
    lifted = []
    for key, ent in sorted(functions.items()):
        if ent.get("status") == "lifted" and ent.get("path"):
            p = os.path.join(ROOT, ent["path"])
            if os.path.exists(p):
                lifted.append((int(key, 16), ent["path"], ent.get("cc", rebuild_check.fn.DEFAULT_CC),
                               ent.get("flags", rebuild_check.fn.DEFAULT_FLAGS)))
    if limit:
        lifted = lifted[:limit]
    all_entries = entries + lifted
    # serialized through the repo-wide compiler lock; one armcc call per
    # function (--jobs 1 discipline: never parallel wine instances)
    with file_lock(LOCK):
        rebuild_check.OBJDIR = OBJDIR  # separate object cache: a lifted stub must never
        os.makedirs(OBJDIR, exist_ok=True)  # be mistaken for a matched object in logs/rebuild/obj
        image, compiled = rebuild_check.assemble_image(all_entries)
    load_binary(code_bin)  # SHA-1 re-verified read-only path, same as the gate
    out_path = os.path.abspath(out_path)
    atomic_write_bytes(out_path, image)
    sha = hashlib.sha1(image).hexdigest()
    state = load_state()
    record = {"out": os.path.relpath(out_path, ROOT), "entries": len(all_entries),
              "matched_entries": len(entries), "lifted_entries": len(lifted),
              "compiled": compiled, "sha1": sha, "bytes": len(image)}
    state["builds"].append(record)
    state["runs"] = state.get("runs", 0) + 1
    save_state(state)
    if as_json:
        print(json.dumps(record))
    else:
        print("hybrid image: %s (%d bytes, SHA-1 %s)" % (record["out"], len(image), sha))
        print("  layers: %d matched + %d lifted sources recompiled (%d placed), rest original code.bin bytes"
              % (len(entries), len(lifted), compiled))
        print("  testing artifact only - rebuild_check.py remains the byte-exact gate")
        print("NEXT  uv run python tools/hybrid_build.py report --json")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", nargs="?", choices=("check", "build", "report"), default="build",
                    help="check = offline plan (no armcc/code.bin); build = full image (default)")
    ap.add_argument("--check", action="store_true", help="alias for the check command")
    ap.add_argument("--out", default=DEFAULT_OUT, help="output image (default build/hybrid.bin; never code.bin)")
    ap.add_argument("--include-hacks", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.cmd == "check" or args.check:
        return cmd_check(args.json)
    if args.cmd == "report":
        return cmd_report(args.json)
    return cmd_build(args.out, args.include_hacks, args.limit, args.json)


if __name__ == "__main__":
    sys.exit(main() or 0)
