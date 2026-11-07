"""Behavioral-oracle wrapper: verify one RECOMP_OVERRIDE against the original
game function using 3dsrecomp's verify harness (Zakuro interpreter as ground
truth), on the user's own decrypted USA ALBW ROM.

  python tools/behavioral_oracle.py build <addr> <c-file>   # compile minilib .so
  python tools/behavioral_oracle.py verify <addr> [--so PATH] [--count N]
  python tools/behavioral_oracle.py verify <addr> --from-repo <src-path>
                                                  # translate a matched
                                                  # decomp source into an
                                                  # override skeleton

Prereqs (scratch, not committed):
  - ~/zakuro-work/3dsrecomp-src: git clone --depth 1 https://github.com/fearkov/3dsrecomp
    cargo build --release --features verify   (rust >= 1.95; works on Termux)
  - ~/zakuro-work/minilib/{recomp.h,entries.c}: recomp.h copied from
    3dsrecomp-src/abi/recomp.h; entries.c hand-written (see docstring of
    build_minilib() below) exporting recomp_abi/entries for the title id.
  - decrypted ROM found via --rom / $ALBW_ROM / ~/Download/*Link*Between*Worlds*USA*.3ds

How it works (3dsrecomp src/verify.rs): for each sampled run, registers
r0-r12 are seeded randomly (heap pointers into a made-up heap), sp/lr/pc set,
then the function runs TWICE from identical state — once in Zakuro's
interpreter (ground truth), once through the recompiled library entry — and
registers, flags, VFP state, writable memory and fault counts are diffed.
VERIFY_ONLY=<hex addr> restricts sampling to one function.

Validated 2026-11-07: 0010F1F8 override (list unlink, replicating final
flags of the last cmp + r1=0 + memory writes) → `1 returned, 0 mismatched`
over 125 sampled runs. A no-op override reports the expected register/
flag/memory mismatches, proving the harness dispatches and diffs correctly.
"""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import ROOT

SCRATCH = os.path.expanduser("~/zakuro-work")
RECOMP = os.path.join(SCRATCH, "3dsrecomp-src", "target", "release", "3dsrecomp")
MINILIB = os.path.join(SCRATCH, "minilib")
DEFAULT_SO = os.path.join(MINILIB, "00040000C30E00.so")
TITLE_ID = "00040000C30E00"

ENTRIES_C = """\
/* hand-written ABI export table for the minilib (abi/src/lib.rs Library::open).
 * generation 0 (<3) makes 3dsrecomp ignore recomp_origins, which otherwise
 * needs a full Origins table and segfaults when null-checked wrong. */
#include <stdint.h>
typedef void (*Code)(void*);
typedef struct { uint32_t address; Code code; } Entry;
typedef struct { const char* name; uint32_t* base; uint32_t size; uint32_t count; const Entry* entries; } Module;
extern void override_0x%(addr)s(void*);
const uint32_t recomp_abi = 5;
const uint32_t recomp_generation = 0;
const uint32_t recomp_entry_count = 1;
const Entry recomp_entries[1] = { { 0x%(addr)s, (Code)override_0x%(addr)s } };
const uint32_t recomp_module_count = 0;
const Module recomp_modules[1] = { { 0, 0, 0, 0, 0 } };
"""


def find_rom(args_rom):
    import glob
    if args_rom:
        return args_rom
    if os.environ.get("ALBW_ROM"):
        return os.environ["ALBW_ROM"]
    for d in [os.environ.get("ALBW_ROMS_DIR", ""), os.path.expanduser("~/Download"),
              "/storage/emulated/0/Download", os.path.join(SCRATCH)]:
        if not d:
            continue
        hits = sorted(glob.glob(os.path.join(d, "*Link*Between*Worlds*USA*.3ds")))
        if hits:
            return hits[0]
    return None


def cmd_build(args):
    addr = args.addr.upper()
    if not addr.startswith("0X"):
        addr = "0x" + addr
    entries = os.path.join(MINILIB, "entries.c")
    with open(entries, "w", encoding="utf-8") as f:
        f.write(ENTRIES_C % {"addr": addr[2:]})
    cc = os.environ.get("CC", "gcc")
    out = args.so or os.path.join(MINILIB, TITLE_ID + ".so")
    ov = os.path.join(MINILIB, "ov.c")
    if not os.path.exists(ov):
        print("missing %s — write your RECOMP_OVERRIDE there first" % ov, file=sys.stderr)
        return 2
    cmd = [cc, "-shared", "-fPIC", "-O2", "-o", out, ov, entries]
    print(" ".join(cmd))
    rc = subprocess.run(cmd, cwd=MINILIB).returncode
    if rc == 0:
        print("built", out)
    return rc


def cmd_verify(args):
    rom = find_rom(args.rom)
    if not rom:
        print("no decrypted USA ROM found; pass --rom", file=sys.stderr)
        return 2
    so = args.so or DEFAULT_SO
    if not os.path.exists(RECOMP):
        print("3dsrecomp binary missing at %s\nclone+build: git clone --depth 1 "
              "https://github.com/fearkov/3dsrecomp ~/zakuro-work/3dsrecomp-src && "
              "cd there && cargo build --release --features verify" % RECOMP, file=sys.stderr)
        return 2
    env = dict(os.environ)
    env["VERIFY_ONLY"] = args.addr.upper()
    cmd = [RECOMP, "verify", rom, so, str(args.count)]
    print(" ".join(cmd), " (VERIFY_ONLY=%s)" % env["VERIFY_ONLY"])
    rc = subprocess.run(cmd, env=env).returncode
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("build", help="compile ov.c + entries.c into the minilib .so")
    p.add_argument("addr", help="function address, e.g. 0010F1F8")
    p.add_argument("--so")
    p.set_defaults(func=cmd_build)
    p = sub.add_parser("verify", help="run 3dsrecomp verify for one address")
    p.add_argument("addr")
    p.add_argument("--so")
    p.add_argument("--rom")
    p.add_argument("--count", type=int, default=500)
    p.set_defaults(func=cmd_verify)
    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
