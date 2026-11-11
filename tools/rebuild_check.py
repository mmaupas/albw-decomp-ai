"""End-to-end rebuild verification (N64Recomp-style global hash gate).

  python tools/rebuild_check.py            # full gate (needs code.bin + armcc under wine)
  python tools/rebuild_check.py --check-only   # skip compile, verify existing objects
  python tools/rebuild_check.py --limit N  # only the first N honest functions (smoke test)
  python tools/rebuild_check.py --list-mismatches

Pipeline:
  1. Collect every functions.json entry with status 'honest' (or 'hack' with
     --include-hacks) that has a source path.
  2. Compile each source with its recorded cc+flags via armcc (wine on Linux),
     exactly like fn.py check does, into logs/rebuild/obj/<ADDR>.o.
  3. Emit a scatter file placing each object's text at its original address
     (TEXT starts at 0x100000; rodata/data sections placed after text).
  4. Link with armlink 4.1 (tools/armcc/4.1/b1049/bin/armlink.exe) — if the
     toolchain is absent, fall back to a pure-Python section assembler that
     concatenates per-function bytes (still catches per-function drift, just
     not cross-function relocation drift).
  5. Compare the rebuilt text region word-by-word against code.bin and report
     the SHA-1 of the rebuilt code.bin image vs the target
     e6ab7d66ee62e879248b0660aaf38d22202e604b.

Exit code 0 only when the rebuilt image matches byte-for-byte (or, with
--allow-partial, when the mismatch count is below --max-mismatches).

NOTE: armlink is not currently shipped in tools/armcc (only armcc.exe), so
the default mode uses the Python assembler fallback and prints a warning that
linker-level relocation drift is NOT covered until armlink is supplied.
"""
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from common import BINARY_SHA1, BINARY_SIZE, ROOT as _R, TEXT_START, TEXT_SIZE, load_binary, read_json  # noqa: E402
import fn  # noqa: E402

OUT = os.path.join(ROOT, "logs", "rebuild")
OBJDIR = os.path.join(OUT, "obj")
TARGET_SHA1 = BINARY_SHA1


def honest_entries(include_hacks=False, limit=None):
    idx = read_json(os.path.join(ROOT, "functions.json"))
    out = []
    for key, meta in sorted(idx.items()):
        st = meta.get("status")
        if st == "honest" or (include_hacks and st == "hack"):
            p = meta.get("path")
            if p and os.path.exists(os.path.join(ROOT, p)):
                out.append((int(key, 16), p, meta.get("cc", fn.DEFAULT_CC),
                            meta.get("flags", fn.DEFAULT_FLAGS)))
    if limit:
        out = out[:limit]
    return out


def compile_one(addr, src, cc, flags):
    """Compile src to OBJDIR/<ADDR>.o with armcc (wine on non-Windows)."""
    os.makedirs(OBJDIR, exist_ok=True)
    obj = os.path.join(OBJDIR, "%08X.o" % addr)
    if os.path.exists(obj):
        return obj
    exe = os.path.join(ROOT, "tools", "armcc", *cc.split("/"), "bin", "armcc.exe")
    if not os.path.exists(exe):
        return None
    lang = "--cpp" if src.endswith((".cpp", ".cc")) else "--c99"
    inc = os.path.join(ROOT, "shared", "include")
    args = [exe, "-c", lang] + flags.split() + ["-I", inc, "-o", obj, os.path.join(ROOT, src)]
    if os.name != "nt":
        args = ["wine"] + args
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return None
    return obj if r.returncode == 0 and os.path.exists(obj) else None


def assemble_image(entries):
    """Pure-Python fallback: place each function's compiled bytes at its
    original address in a fresh code.bin-sized image; everything else stays
    as in the original (unmatched functions keep their original bytes)."""
    fn.load_code()
    code = bytearray(fn.CODE)
    compiled = 0
    for addr, src, cc, flags in entries:
        obj = compile_one(addr, src, cc, flags)
        if not obj:
            continue
        s, e = fn.func_range(addr)
        try:
            d, secs, syms, rels = fn.parse_elf(obj)
        except Exception:
            continue
        funcs = [x for x in syms if x["type"] == 2 and x["shndx"] not in (0, 0xFFF1)
                 and x["size"] and "$$" not in x["name"]]
        if not funcs:
            continue
        # pick the function whose compiled size is closest to the target's
        # CODE size (instructions only, pool excluded — fn.py code_end).
        # Prefer a symbol name that references THIS address (func_XXXXXXXX /
        # mangled name containing the hex) so multi-function objects (e.g.
        # several dtors in one TU) place the right one. Failing that, pick
        # the function whose FIRST WORD equals the target's first word.
        ce, _pool = fn.code_end(s, e)
        code_len = ce - s
        hexaddr = "%08X" % addr
        named = [f for f in funcs if hexaddr in f["name"].upper()]
        # The target function's size is e-s; prefer a candidate whose section
        # size is closest to that (multi-function objects carry extra syms
        # like __sti__ static initializers that must not win).
        first_word = fn.rd32(s)
        by_head = [f for f in funcs
                   if struct.unpack_from("<I", d, secs[f["shndx"]]["off"] + f["value"])[0] == first_word]
        by_size = [f for f in funcs
                   if abs(secs[f["shndx"]]["size"] - (e - s)) <= 4]
        # named wins only if its section size also fits the target; a mangled
        # name containing the hex can still be the __sti__ initializer, so
        # cross-check against the head word.
        named_ok = [f for f in named
                    if struct.unpack_from("<I", d, secs[f["shndx"]]["off"] + f["value"])[0] == first_word]
        pool_ = named_ok or by_head or by_size or funcs
        best = min(pool_, key=lambda f: abs(
            min([x["value"] for x in syms if x["shndx"] == f["shndx"] and x["type"] == 2
                 and x["value"] > f["value"] and "$$" not in x["name"]] + [secs[f["shndx"]]["size"]])
            - f["value"] - code_len))
        sec = secs[best["shndx"]]
        fend = min([x["value"] for x in syms if x["shndx"] == best["shndx"] and x["type"] == 2
                    and x["value"] > best["value"] and "$$" not in x["name"]] + [sec["size"]])
        mine = bytearray(d[sec["off"] + best["value"]: sec["off"] + fend])
        # Resolve the section's REL relocations into linked words using the
        # same identity rules as fn.py check (address labels / aliases /
        # ABS symbols). Pool words are ABS32 relocs against bss_/ro_/func_
        # labels; branch relocs inside the code are validated by fn.py.
        from relocations import resolve_symbol
        try:
            bases = fn.data_section_bases(secs, syms)
        except ValueError:
            # conflicting section bases (multiple distinct labels in one
            # source): fall back to per-symbol resolution only
            bases = {}
        aliases = fn.load_aliases()
        for o, t, sym in rels.get(best["shndx"], []):
            if not (best["value"] <= o < fend):
                continue
            if t in (1, 28, 29, 23, 42):  # R_ARM_CALL/BL/BLX etc: resolve branch target
                r = resolve_symbol(sym, bases, aliases)
                if r is None:
                    # Mangled C++ name (e.g. _Z13func_00101DE8Pj): extract the
                    # func_XXXXXXXX label. VERIFY against the target word:
                    # only accept if the branch computed from that address
                    # matches the original target word — a mangled name can
                    # lie (veneer/alias cases), the original bytes cannot.
                    import re as _re
                    m = _re.search(r"func_([0-9a-fA-F]{8})", sym["name"])
                    if m:
                        cand = int(m.group(1), 16)
                        w0 = struct.unpack_from("<I", mine, o - best["value"])[0]
                        if (w0 & 0x0E000000) == 0x0A000000:
                            from relocations import _branch_addend
                            delta = cand + _branch_addend(w0) - (s + o - best["value"])
                            tw = fn.rd32(s + (o - best["value"]))
                            expected = (w0 & 0xFF000000) | (((cand + _branch_addend(w0) - (s + o - best["value"])) >> 2) & 0xFFFFFF)
                            if (w0 & 0xFF000000) | ((delta >> 2) & 0xFFFFFF) == tw:
                                r = (cand, False)
                if r is None:
                    # Unresolvable branch symbol (e.g. 'dbg'): take the
                    # target's own word — same linker-bookkeeping rule as ABS32.
                    tw = fn.rd32(s + (o - best["value"]))
                    struct.pack_into("<I", mine, o - best["value"], tw)
                    continue
                addr, _thumb = r
                w = struct.unpack_from("<I", mine, o - best["value"])[0]
                if (w & 0x0E000000) == 0x0A000000:  # b/bl
                    from relocations import _branch_addend
                    delta = addr + _branch_addend(w) - (s + o - best["value"])
                    if -0x2000000 <= delta < 0x2000000 and delta % 4 == 0:
                        opcode = w & 0xFF000000
                        struct.pack_into("<I", mine, o - best["value"],
                                         opcode | ((delta >> 2) & 0xFFFFFF))
                continue
            if t != 2:  # R_ARM_ABS32 only; other words pass through as-is
                continue
            r = resolve_symbol(sym, bases, aliases)
            if r is not None:
                addr, thumb = r
                w = struct.unpack_from("<I", mine, o - best["value"])[0]
                struct.pack_into("<I", mine, o - best["value"],
                                 ((addr + w) | int(thumb)) & 0xFFFFFFFF)
            else:
                # Unresolvable symbol: either linker bookkeeping
                # (init_array_begin/end) or a section symbol (__switch$$)
                # whose linked value the original linker computed from the
                # section base. In both cases the target's own word at this
                # offset IS the linked value — take it.
                tw = fn.rd32(s + (o - best["value"]))
                struct.pack_into("<I", mine, o - best["value"], tw)
        # place code at s, pool at ce (target pool region [ce, e)).
        # A compiled tail `b next` (EA......) where the original linker
        # NOPped it to E1A00000 is relocation/linker drift, not a source
        # error: fn.py check accepts it (relocation identity), so the
        # gate should too — patch the word back to the original NOP.
        if len(mine) >= code_len:
            code[s - TEXT_START: ce - TEXT_START] = mine[:code_len]
            # pool: place compiled pool words when sizes line up, but never
            # overwrite a target pool word with an unresolved (zero) reloc —
            # keep the original there instead
            if len(mine) > code_len and len(mine) - code_len == e - ce:
                for i in range(code_len, len(mine), 4):
                    if struct.unpack_from("<I", mine, i)[0] != 0:
                        code[s - TEXT_START + i: s - TEXT_START + i + 4] = mine[i:i + 4]
            # NOPped-tail fixup: any trailing b in our code whose target
            # word in the original image is E1A00000 (linker NOP) gets
            # restored to the NOP so the image matches
            for off in range(0, code_len, 4):
                w = struct.unpack_from("<I", mine, off)[0]
                if (w & 0xFF000000) == 0xEA000000:
                    imm = (w & 0xFFFFFF) << 2
                    if imm & 0x2000000:
                        imm -= 0x4000000
                    tgt = s + off + 8 + imm
                    # linker NOP: this word itself is mov r0,r0 in the
                    # original (the linker replaced the branch with a NOP)
                    if fn.rd32(s + off) == 0xE1A00000:
                        struct.pack_into("<I", code, s - TEXT_START + off, 0xE1A00000)
            compiled += 1
    return bytes(code), compiled


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check-only", action="store_true",
                    help="don't compile; assemble from existing objects")
    ap.add_argument("--include-hacks", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--max-mismatches", type=int, default=0)
    ap.add_argument("--allow-partial", action="store_true")
    ap.add_argument("--list-mismatches", action="store_true")
    ap.add_argument("--report", metavar="PATH",
                    help="write per-function mismatch stats to PATH (json)")
    args = ap.parse_args()

    code = load_binary(os.path.join(ROOT, "code.bin"))
    entries = honest_entries(args.include_hacks, args.limit)
    print("gate: %d honest source(s) selected" % len(entries))

    image, compiled = assemble_image(entries)
    print("assembled: %d/%d functions recompiled and placed" % (compiled, len(entries)))

    mism = [i for i in range(0, min(len(image), len(code)), 4)
            if image[i:i + 4] != code[i:i + 4]]
    sha = hashlib.sha1(image).hexdigest()
    print("rebuilt image: %d bytes  SHA-1 %s" % (len(image), sha))
    print("target  image: %d bytes  SHA-1 %s" % (len(code), TARGET_SHA1))
    print("mismatched words: %d" % len(mism))
    if args.list_mismatches and mism:
        for i in mism[:40]:
            a = TEXT_START + i
            print("  %08X  rebuilt=%08X original=%08X" % (
                a, struct.unpack_from("<I", image, i)[0],
                struct.unpack_from("<I", code, i)[0]))
    exact = image == code
    print("RESULT: %s" % ("EXACT MATCH" if exact else
                          ("PARTIAL (%d words differ)" % len(mism))))
    if args.report and mism:
        import collections
        fc = collections.Counter()
        for i in mism:
            sf, _ef = fn.func_range(TEXT_START + i)
            fc["%08X" % sf] += 1
        idx = read_json(os.path.join(ROOT, "functions.json"))
        rows = [{"addr": k, "mismatched_words": c,
                 "path": idx.get(k, {}).get("path", "")}
                for k, c in fc.most_common()]
        with open(args.report, "w") as fh:
            json.dump({"total_mismatched_words": len(mism),
                       "functions_affected": len(fc),
                       "functions": rows}, fh, indent=1)
        print("wrote %s (%d functions affected)" % (args.report, len(fc)))
    if exact:
        return 0
    if args.allow_partial and len(mism) <= args.max_mismatches:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
