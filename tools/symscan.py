"""Binary-derived symbol cross-check (ReXGlue-style analysis pass, ARM edition).

  python tools/symscan.py scan [--json]      derive function starts from the
                                             binary itself and cross-check them
                                             against funcs.json
  python tools/symscan.py vtables [--json]   vtable-like runs in rodata/data
  python tools/symscan.py helpers [--json]   __aeabi_/armlib runtime signatures

Three independent derivations, all offline and read-only over code.bin:

  exidx    the .ARM.exidx table at the tail of .data (0x6FD000-0x6FF000) is a
           list of (prel31 function start, unwind info) pairs. On Xbox 360
           ReXGlue parses .pdata the same way; on ARM the unwind table plays
           the identical role of enumerating function boundaries.
  vtables  runs of >= 3 consecutive aligned text pointers in rodata/data are
           C++ vtables (ReXGlue's VTableScanner analogue). Their entries are
           virtual-function starts.
  helpers  armcc/armlib runtime leaf signatures (__aeabi_memclr4, memset
           wrapper, division helpers) matched by their documented instruction
           idioms, generalizing the LESSONS.md armlib memfunc disposal.

`scan` reports: how many exidx-derived starts are already in funcs.json,
how many are missing (candidates for interior entries or mis-splits), and
how many exidx functions have a symbol in shared/symbols.jsonl. Exit code is
0 when nothing is missing, 1 otherwise, so it can gate CI-style checks.
"""
import argparse
import json
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fn
from common import ROOT, read_json

EXIDX_LO, EXIDX_HI = 0x6FD000, 0x6FF000  # .ARM.exidx + .ARM.extab live at the tail of .data
VTABLE_MIN_RUN = 3


def prel31(addr, word):
    value = word & 0x7FFFFFFF
    if word & 0x80000000:
        value -= 0x80000000
    return addr + value


def scan_exidx():
    """(entry address, function start, unwind word) for every exidx pair."""
    code = fn.load_code()
    words = struct.unpack_from("<%dI" % ((EXIDX_HI - EXIDX_LO) // 4), code, EXIDX_LO - fn.TA)
    out = []
    for i in range(0, len(words) - 1, 2):
        entry_addr = EXIDX_LO + i * 4
        start = prel31(entry_addr, words[i])
        if fn.in_text(start) and not (start & 3):
            out.append((entry_addr, start, words[i + 1]))
    return out


def scan_vtables():
    """Runs of >= VTABLE_MIN_RUN aligned text pointers in rodata and data."""
    code = fn.load_code()
    out = {}
    for base, size, name in ((fn.RA, fn.RS, "rodata"), (fn.DA, fn.DS, "data")):
        words = struct.unpack_from("<%dI" % (size // 4), code, base - fn.TA)
        run = []
        tables = []
        for i, w in enumerate(words):
            addr = base + i * 4
            if fn.in_text(w) and not (w & 1):
                run.append((addr, w))
            else:
                if len(run) >= VTABLE_MIN_RUN:
                    tables.append(run)
                run = []
        if len(run) >= VTABLE_MIN_RUN:
            tables.append(run)
        out[name] = tables
    return out


def _ends_bx_lr(code, addr):
    w = struct.unpack_from("<I", code, addr - fn.TA)[0]
    return (w & 0xFFFFFFF0) == 0xE12FFF10  # bx lr


def scan_helpers():
    """Classify known armlib runtime signatures by instruction idiom.

    Anchors come from docs/LESSONS.md "armlib memfunc cluster" (2026-10-27):
    0x110490 __aeabi_memclr4 (lr carried in the stm fill list), 0x1164F4
    __aeabi_memclr, 0x1164A8 memset wrapper (push {r0,lr} at +4, then a tail
    bl into the memclr core — the push/pop idiom is unique in the binary).
    """
    code = fn.load_code()
    starts = set(fn.STARTS)
    out = {"leaf_bx_lr": 0, "memclr4_anchor": False, "memclr_anchor": False,
           "memset_wrapper_anchor": False, "push_r0_lr_count": 0}
    words = struct.unpack_from("<%dI" % (len(code) // 4), code, 0)
    out["push_r0_lr_count"] = sum(1 for w in words if w == 0xE92D4001)  # push {r0, lr}
    for s in fn.STARTS:
        end = fn.func_range(s)[1]
        if end - s > 0x40:
            continue
        if _ends_bx_lr(code, end - 4):
            out["leaf_bx_lr"] += 1
    # memclr4 anchor: `mov lr, r2` (E1A0E002) followed by conditional
    # `stmhs r0!, {r2, r3, ip, lr}` fill words (0x?8A0500C with lr set after
    # zeroing) — armcc C never clobbers lr mid-body, so this idiom is
    # library-only (LESSONS.md, 2026-10-27). The stored fill value is lr
    # itself, loaded from r2, so the register list is 0x500C with the lr
    # bit expressed via the mov into lr, not the list bit.
    s, e = fn.func_range(0x110490)
    ws = [struct.unpack_from("<I", code, a - fn.TA)[0] for a in range(s, e, 4)]
    mov_lr = 0xE1A0E002 in ws
    stm_fill = any((w & 0x0FFFFF0F) == 0x08A0500C for w in ws)
    out["memclr4_anchor"] = mov_lr and stm_fill
    # memset wrapper: `and r1,r1,#0xff` broadcast, `mov r1,r2`, push {r0,lr}
    # at +8, orr/shift broadcasts, a bl into the memclr core at +0x14, and a
    # pop {r0,pc} epilogue — the push {r0,lr} idiom is unique to armlib.
    w = [struct.unpack_from("<I", code, 0x1164A8 + i * 4 - fn.TA)[0] for i in range(8)]
    out["memset_wrapper_anchor"] = (w[0] == 0xE20130FF and w[2] == 0xE92D4001
                                    and (w[5] & 0x0F000000) == 0x0B000000
                                    and w[6] == 0xE8BD8001)  # pop {r0, pc}
    out["memclr_anchor"] = 0x1164F4 in starts
    return out


def cmd_scan(as_json=False):
    entries = scan_exidx()
    starts = set(fn.STARTS)
    syms = fn.known_symbols()
    derived = {start for _, start, _ in entries}
    missing = sorted(derived - starts)
    # exidx only covers compiler-generated C++ (functions with unwind info);
    # armlib asm and Thumb helpers have no exidx entry, so restrict the
    # symbol-coverage statistic to the exidx-derived set itself.
    named = sum(1 for s in derived if s in syms)
    unwound = len(derived & starts)
    result = {
        "exidx_entries": len(entries),
        "exidx_distinct_functions": len(derived),
        "already_in_funcs_json": unwound,
        "missing_from_funcs_json": len(missing),
        "missing": ["%08X" % m for m in missing],
        "exidx_functions_with_symbol": named,
        "total_symbols": len(syms),
    }
    if as_json:
        print(json.dumps(result, indent=1))
    else:
        print("exidx entries:            %d" % result["exidx_entries"])
        print("distinct functions:       %d" % result["exidx_distinct_functions"])
        print("already in funcs.json:    %d" % result["already_in_funcs_json"])
        print("missing from funcs.json:  %d" % result["missing_from_funcs_json"])
        for m in result["missing"]:
            print("  MISSING %s" % m)
        print("exidx fns with a symbol:  %d (of %d symbols total)"
              % (result["exidx_functions_with_symbol"], result["total_symbols"]))
    return 0 if not missing else 1


def cmd_vtables(as_json=False):
    tables = scan_vtables()
    starts = set(fn.STARTS)
    result = {}
    for region, runs in tables.items():
        entries = [w for run in runs for _, w in run]
        result[region] = {
            "vtable_runs": len(runs),
            "virtual_entries": len(entries),
            "entries_in_funcs_json": sum(1 for e in entries if e in starts),
            "entries_not_starts": ["%08X" % e for e in entries if e not in starts],
        }
    if as_json:
        print(json.dumps(result, indent=1))
    else:
        for region, r in result.items():
            print("%s: %d vtable runs, %d virtual entries, %d already starts, %d not starts"
                  % (region, r["vtable_runs"], r["virtual_entries"],
                     r["entries_in_funcs_json"], len(r["entries_not_starts"])))
            for e in r["entries_not_starts"][:20]:
                print("  NOT-A-START %s" % e)
    return 0


def cmd_helpers(as_json=False):
    result = scan_helpers()
    if as_json:
        print(json.dumps(result, indent=1))
    else:
        for k, v in result.items():
            print("%s: %s" % (k, v))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["scan", "vtables", "helpers"])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    rc = {"scan": cmd_scan, "vtables": cmd_vtables, "helpers": cmd_helpers}[args.cmd](args.json)
    sys.exit(rc)


if __name__ == "__main__":
    main()
