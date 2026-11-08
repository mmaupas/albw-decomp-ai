"""ALBW matching-decomp helper.

  python tools/fn.py show  <addr>                 annotated disassembly of the target function
  python tools/fn.py xref  <addr>                 who calls / references an address
  python tools/fn.py check <file.cpp> <addr> [--sym SUBSTR] [--cc 4.1/b894] [--flags "..."]
                                                   compile with ARMCC and compare against the original
"""
import bisect, difflib, json, os, re, struct, subprocess, sys, time

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
except ImportError:
    Cs = None

from common import ROOT, TEXT_SIZE, TEXT_START, file_lock, load_binary, read_json, write_json
from relocations import word_matches

_code_path = os.path.join(ROOT, "code.bin")
CODE = None
TA, TS = TEXT_START, TEXT_SIZE
RA, RS = 0x693000, 439800
DA, DS = 0x6FF000, 166384
TEXT_END = TA + TS
DEFAULT_CC = "4.1/b1049"  # b894 inserts NOPs between back-to-back branches; b791..b1454 (except b894) match
DEFAULT_FLAGS = "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections"

md = Cs(CS_ARCH_ARM, CS_MODE_ARM) if Cs else None


def load_code():
    global CODE
    if CODE is None:
        CODE = load_binary(_code_path)
    return CODE


def rd32(a):
    return struct.unpack_from("<I", load_code(), a - TA)[0]


def in_text(a):
    return TA <= a < TEXT_END


def in_ro(a):
    return RA <= a < RA + RS


def in_data(a):
    return DA <= a < DA + DS + 0x200000  # data + generous bss


_cache = os.path.join(ROOT, "funcs.json")


def build_table():
    load_code()
    words = struct.unpack_from(f"<{TS // 4}I", CODE, 0)
    bl, ptr, pro = set(), set(), set()
    for i, w in enumerate(words):
        if (w & 0x0F000000) == 0x0B000000 and (w >> 28) != 0xF:
            imm = w & 0xFFFFFF
            imm = imm - 0x1000000 if imm & 0x800000 else imm
            t = TA + i * 4 + 8 + (imm << 2)
            if in_text(t):
                bl.add(t)
        if (w & 0xFFFF4000) == 0xE92D4000 or w == 0xE52DE004:
            pro.add(TA + i * 4)
    for lo, sz in ((RA, RS), (DA, DS)):
        n = sz // 4
        for w in struct.unpack_from(f"<{n}I", CODE, lo - TA):
            if in_text(w) and not w & 3:
                ptr.add(w)

    def is_end(w):
        return (w == 0xE12FFF1E or (w & 0xFFFF8000) == 0xE8BD8000 or w == 0xE49DF004
                or (w & 0xFF000000) == 0xEA000000 or w == 0 or (w & 0xFFFFFFF0) == 0xE12FFF10)

    # literal-pool words: targets of PC-relative LDR / VLDR
    pool = set()
    for i, w in enumerate(words):
        if (w & 0x0F7F0000) == 0x051F0000 or (w & 0x0F3F0E00) == 0x0D1F0A00:
            off = (w & 0xFFF) if (w & 0x0F000000) == 0x05000000 else (w & 0xFF) * 4
            pool.add(TA + i * 4 + 8 + (off if w & 0x00800000 else -off))
        elif (w & 0x0FEF0000) in (0x028F0000, 0x024F0000):  # ADR: inline string/data, mark until its NUL
            rot = ((w >> 8) & 0xF) * 2
            v = ((w & 0xFF) >> rot | (w & 0xFF) << (32 - rot)) & 0xFFFFFFFF if rot else w & 0xFF
            t = TA + i * 4 + 8 + (v if (w & 0x0FEF0000) == 0x028F0000 else -v)
            t &= ~3
            for _ in range(64):
                if not in_text(t):
                    break
                pool.add(t)
                if 0 in struct.pack("<I", rd32(t)):
                    break
                t += 4

    def stops(i):
        """True if the word at index i ends a function: unconditional return/branch, pool data or padding."""
        w = words[i]
        return (is_end(w) or (w & 0xFFFFF000) == 0xE59FF000 or w == 0xE1A00000
                or (TA + i * 4) in pool)

    # pointer targets count when preceded by a return/branch or by literal-pool data
    ptr_ok = {a for a in ptr if a == TA or stops((a - TA) // 4 - 1)}
    starts = sorted(pro | bl | ptr_ok)
    # tail-call-only functions (leaf functions reached by a plain "b" from another function):
    # the target follows a stop and the branch comes from a different function
    tail = set()
    for i, w in enumerate(words):
        if (w & 0x0F000000) == 0x0A000000 and (w >> 28) != 0xF:
            imm = w & 0xFFFFFF
            imm = imm - 0x1000000 if imm & 0x800000 else imm
            src = TA + i * 4
            t = src + 8 + (imm << 2)
            if (in_text(t) and t > TA and t not in pool and stops((t - TA) // 4 - 1)
                    and bisect.bisect_right(starts, src) != bisect.bisect_right(starts, t)):
                # a real entry never reads the caller's frame before its own push / sub sp
                j = (t - TA) // 4
                frame = False
                for k in range(j, min(j + 6, len(words))):
                    x = words[k]
                    if (x & 0xFFFF0000) in (0xE92D0000, 0xE24DD000) or x == 0xE52DE004 or (x & 0xFFBF0F00) == 0xED2D0B00:
                        break
                    if (x & 0x0C0F0000) == 0x040D0000 and (x & 0xFFF) and (x >> 28) != 0xF:
                        frame = True  # ldr/str [sp, #imm] before any frame setup
                        break
                if not frame:
                    tail.add(t)
    starts = sorted(a for a in set(starts) | tail if a not in pool)  # a literal-pool word is never a function start
    # starts nothing references (e.g. a setter reached only through a linker-NOPped forwarder), added by hand
    xf = os.path.join(ROOT, "shared", "extra_starts.txt")
    extra = set()
    if os.path.exists(xf):
        extra = {int(l.split()[0], 16) for l in open(xf) if l.strip() and not l.startswith("#")}
        starts = sorted(set(starts) | {a for a in extra if in_text(a)})
    fixed = set()
    for k, a in enumerate(starts):
        i = (a - TA) // 4
        if k == 0 or stops(i - 1) or a in extra:  # hand-verified starts stay (e.g. after a 0xFFFFFFFF pool word)
            fixed.add(a)
            continue
        # ARMCC may schedule up to 3 unconditional instructions before the push:
        # the real start follows the previous stop
        for back in (1, 2, 3):
            if i - back - 1 < 0 or (words[i - back] >> 28) != 0xE:
                break  # conditional code before the push: shrink-wrapped, same function
            if stops(i - back - 1):
                fixed.add(a - 4 * back)
                break
        # otherwise the previous code falls through into it (e.g. a shrink-wrapped push): same function
    starts = sorted(fixed)
    # false starts (an internal basic block that our heuristics took for a function), removed by hand
    nf = os.path.join(ROOT, "shared", "not_starts.txt")
    if os.path.exists(nf):
        drop = {int(l.split()[0], 16) for l in open(nf) if l.strip() and not l.startswith("#")}
        starts = sorted(set(starts) - drop)
    write_json(_cache, {"starts": starts, "bl": sorted(bl), "ptr": sorted(ptr)})


if not os.path.exists(_cache):
    raise RuntimeError("funcs.json is missing; importing tooling never rebuilds it implicitly")
_t = read_json(_cache)
STARTS = _t["starts"]
BL_T = set(_t["bl"])
PTR_T = set(_t["ptr"])


def func_range(addr):
    i = bisect.bisect_right(STARTS, addr) - 1
    s = STARTS[i]
    e = STARTS[i + 1] if i + 1 < len(STARTS) else TEXT_END
    return s, e


def cstring(a):
    load_code()
    off = a - TA
    end = CODE.find(b"\0", off, off + 200)
    if end <= off:
        return None
    s = CODE[off:end]
    try:
        t = s.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(t) >= 2 and all(c.isprintable() for c in t):
        return t
    return None


SYMS_FILE = os.path.join(ROOT, "shared", "symbols.jsonl")


def known_symbols():
    """Names/signatures agents have registered with `kb.py sym` (latest entry per address wins)."""
    out = {}
    if os.path.exists(SYMS_FILE):
        with open(SYMS_FILE, encoding="utf-8") as stream:
            for line in stream:
                try:
                    d = json.loads(line)
                    out[int(d["addr"], 16)] = d
                except (ValueError, KeyError):
                    pass
    return out


_SYMS = known_symbols()


def name_of(a):
    if in_text(a):
        s, _ = func_range(a)
        base = f"func_{a:08X}" if s == a else f"func_{s:08X}+{a - s:#x}"
        k = _SYMS.get(a)
        return f"{base} <{k['name']}>" if k else base
    if a in _SYMS:
        return f"{a:08X} <{_SYMS[a]['name']}>"
    if in_ro(a):
        st = cstring(a)
        return f'ro_{a:08X} "{st}"' if st else f"ro_{a:08X}"
    if in_data(a):
        return f"data_{a:08X}" if a < DA + DS else f"bss_{a:08X}"
    return None


def dis1(a):
    """Decode the single ARM word at a (None if it is not a valid instruction)."""
    if md is None:
        raise RuntimeError("Disassembly requires capstone; install requirements.txt")
    l = list(md.disasm(load_code()[a - TA:a - TA + 4], a, 1))
    return l[0] if l else None


def code_end(start, end):
    """Split [start,end) into instructions and trailing literal pool (words loaded PC-relative)."""
    pool = set()
    for a in range(start, end, 4):
        ins = dis1(a)
        if ins is None:
            continue
        m = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", ins.op_str)
        if m and ins.mnemonic.startswith(("ldr", "vldr")):
            tgt = ins.address + 8 + int(m.group(1), 0)
            if start <= tgt < end:
                pool.add(tgt & ~3)
    ce = end
    while ce - 4 >= start and (ce - 4) in pool:
        ce -= 4
    return ce, pool


_tiny = None


def tiny_getters():
    """Getters 'ldr*  r0, [r0, #imm]; bx lr' that armlink --inline copies into their callers.
    Maps the load word to the getter address (only words unique to one getter)."""
    global _tiny
    if _tiny is None:
        seen = {}
        for a in range(TA + 4, TA + TS - 4, 4):
            w = rd32(a)
            if rd32(a + 4) != 0xE12FFF1E or (w >> 28) != 0xE or (w >> 12) & 0xFF != 0:  # Rn = r0, Rd = r0
                continue
            ld = ((w & 0x0F100000) in (0x05100000, 0x07100000) or  # ldr / ldrb, ldr reg-offset
                  (w & 0x0F1000F0) in (0x011000B0, 0x011000D0, 0x011000F0))  # ldrh / ldrsb / ldrsh
            p = rd32(a - 4)
            if ld and (p in (0xE12FFF1E, 0xE1A00000) or (p & 0xFFFF8000) == 0xE8BD8000 or (p & 0xFF000000) == 0xEA000000):
                seen.setdefault(w, []).append(a)
        _tiny = {w: v[0] for w, v in seen.items() if len(v) == 1}
    return _tiny


def listing(start, end, data_words=None):
    """Return list of (addr, word, text) for [start,end)."""
    ce, pool = code_end(start, end)
    out = []
    for a in range(start, ce, 4):
        ins = dis1(a)
        if ins is None or a in pool:  # data inside the code (jump-table data, inline pool)
            out.append((a, rd32(a), f".word {rd32(a):#010x}"))
            continue
        txt = f"{ins.mnemonic:8} {ins.op_str}"
        note = ""
        if ins.mnemonic.startswith(("bl", "b")) and ins.op_str.startswith("#"):
            t = int(ins.op_str[1:], 0)
            if not (start <= t < end):
                note = name_of(t) or ""
            else:
                note = f"<+{t - start:#x}>"
        m = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", ins.op_str)
        if m:
            la = ins.address + 8 + int(m.group(1), 0)
            if in_text(la):
                v = rd32(la & ~3)
                note = f"={v:#x} {name_of(v) or ''}".rstrip()
        if not note and a > start:
            g = tiny_getters().get(rd32(a))
            if g and g != start:
                note = f"maybe linker-inlined call to {name_of(g) or f'func_{g:08X}'} (KB #111)"
        if note:
            txt += f"   ; {note}"
        out.append((ins.address, rd32(ins.address), txt))
    for a in range(ce, end, 4):
        v = rd32(a)
        n = name_of(v)
        out.append((a, v, f".word {v:#010x}" + (f"   ; {n}" if n else "")))
    return out


def cmd_show(addr):
    s, e = func_range(addr)
    refs = []
    if s in BL_T:
        refs.append("called by BL")
    if s in PTR_T:
        refs.append("address stored in ro/data (vtable or callback)")
    print(f"func_{s:08X}  size {e - s:#x} ({e - s} bytes)  [{', '.join(refs) or 'no direct refs found'}]")
    for a, w, t in listing(s, e):
        print(f"  {a:08X}: {w:08X}  {t}")


def cmd_xref(addr):
    load_code()
    hits = []
    words = struct.unpack_from(f"<{TS // 4}I", CODE, 0)
    for i, w in enumerate(words):
        pc = TA + i * 4
        if (w & 0x0E000000) == 0x0A000000 and (w >> 28) != 0xF:
            imm = w & 0xFFFFFF
            imm = imm - 0x1000000 if imm & 0x800000 else imm
            if pc + 8 + (imm << 2) == addr:
                hits.append(f"  branch from {pc:08X} in {name_of(pc)}")
        elif w == addr:
            hits.append(f"  literal at {pc:08X} in {name_of(pc)}")
    for lo, sz, tag in ((RA, RS, "ro"), (DA, DS, "data")):
        for j in range(0, sz - 3, 4):
            if rd32(lo + j) == addr:
                hits.append(f"  pointer in {tag} at {lo + j:08X}")
    print("\n".join(hits[:60]) or "  no references")
    if len(hits) > 60:
        print(f"  ... {len(hits) - 60} more")


# ---------------- ELF object parsing ----------------
def parse_elf(path):
    with open(path, "rb") as stream:
        d = stream.read()
    if len(d) < 52 or d[:7] != b"\x7fELF\x01\x01\x01" or struct.unpack_from("<HH", d, 16) != (1, 40):
        raise ValueError("expected a little-endian ARM ELF32 relocatable object")
    shoff, = struct.unpack_from("<I", d, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2E)
    if shentsize != 40 or shnum == 0 or shstrndx >= shnum or shoff < 52 or shoff + shnum * shentsize > len(d):
        raise ValueError("invalid ELF section-header table")
    secs = []
    for i in range(shnum):
        nm, ty, fl, ad, off, sz, link, info, al, es = struct.unpack_from("<10I", d, shoff + i * shentsize)
        if ty != 8 and off + sz > len(d):  # SHT_NOBITS has no file payload
            raise ValueError("ELF section extends beyond object")
        secs.append(dict(name=nm, type=ty, flags=fl, off=off, size=sz, link=link, info=info, es=es))
    shs = secs[shstrndx]
    if shs["type"] != 3:
        raise ValueError("invalid ELF section-name string table")

    def sname(o, tab):
        if o >= tab["size"]:
            raise ValueError("ELF string offset outside table")
        e = d.find(b"\0", tab["off"] + o, tab["off"] + tab["size"])
        if e == -1:
            raise ValueError("unterminated ELF string")
        return d[tab["off"] + o:e].decode("latin1")

    for s in secs:
        s["name"] = sname(s["name"], shs)
    syms = []
    tables = {}
    for index, s in enumerate(secs):
        if s["type"] == 2:  # SYMTAB
            if s["es"] != 16 or s["size"] % 16 or s["link"] >= shnum or secs[s["link"]]["type"] != 3:
                raise ValueError("invalid ELF symbol-table layout")
            table = tables[index] = []
            strt = secs[s["link"]]
            for j in range(s["size"] // 16):
                nm, val, sz, info, oth, shn = struct.unpack_from("<IIIBBH", d, s["off"] + j * 16)
                table.append(dict(name=sname(nm, strt), value=val, size=sz,
                                  type=info & 0xF, binding=info >> 4, shndx=shn))
            syms.extend(table)
    rels = {}
    for s in secs:
        if s["type"] == 4:  # RELA is not emitted by our compiler; never ignore it.
            raise ValueError("unsupported ELF RELA relocations")
        if s["type"] == 9:  # REL, sh_link identifies the symbol table
            if s["es"] != 8 or s["size"] % 8 or not 0 < s["info"] < shnum or s["link"] not in tables:
                raise ValueError("invalid ELF relocation-table layout")
            lst = rels.setdefault(s["info"], [])
            table = tables[s["link"]]
            for j in range(s["size"] // 8):
                off, info = struct.unpack_from("<II", d, s["off"] + j * 8)
                if off % 4 or off + 4 > secs[s["info"]]["size"] or any(r[0] == off for r in lst):
                    raise ValueError("unaligned, overlapping or out-of-range ELF relocation")
                if info >> 8 >= len(table):
                    raise ValueError("ELF relocation symbol outside table")
                lst.append((off, info & 0xFF, table[info >> 8]))
    return d, secs, syms, rels


def data_section_bases(secs, syms):
    """Place the object's data sections from explicit address-label symbols.

    A symbol named data_XXXXXXXX / bss_XXXXXXXX / ro_XXXXXXXX is an agent-
    asserted linked address (the naming convention the checker already trusts
    for identity via relocations.resolve_symbol). Deriving the section base
    from such a symbol is the same class of proof: base = asserted - value.
    Fail-closed: only sections containing at least one named label get a base;
    conflicting labels (two symbols asserting different bases) abort the check.
    """
    from relocations import ADDRESS_LABEL
    bases = {}
    for x in syms:
        m = ADDRESS_LABEL.fullmatch(x["name"])
        if not m or x["shndx"] in (0, 0xFFF1):
            continue
        prefix = m.group(0).split("_")[0]
        sec = secs[x["shndx"]]
        # a data/bss label must live in a data-ish section; ro_ in read-only data
        writable = bool(sec["flags"] & 1)  # SHF_WRITE
        if prefix == "ro" and writable:
            _check_abort("ro_ label %s in writable section %s" % (x["name"], sec["name"]))
        if prefix in ("data", "bss") and not writable:
            _check_abort("%s label %s in read-only section %s" % (prefix, x["name"], sec["name"]))
        base = int(m.group(1), 16) - x["value"]
        old = bases.get(x["shndx"])
        if old is not None and old != base:
            _check_abort("conflicting section bases for %s: %08X vs %08X (%s vs %s)"
                         % (sec["name"], old & 0xFFFFFFFF, base & 0xFFFFFFFF,
                            [y["name"] for y in syms if y["shndx"] == x["shndx"]][0], x["name"]))
        bases[x["shndx"]] = base
    return bases


def _check_abort(msg):
    raise ValueError("section-base derivation: " + msg)


ALIASES_FILE = os.path.join(ROOT, "shared", "aliases.json")


def load_aliases():
    """Explicit symbol identities from shared/aliases.json ({name: hexaddr}).

    Unlike address-label names (data_XXXXXXXX), an alias is a reviewed
    identity: the file must exist to have effect, and every entry is an
    assertion an agent (or human) has verified against the game dump."""
    if not os.path.exists(ALIASES_FILE):
        return None
    with open(ALIASES_FILE, encoding="utf-8") as stream:
        d = json.load(stream)
    return {name: int(v, 16) if isinstance(v, str) else int(v) for name, v in d.items()}


def cmd_check(src, addr, sym=None, cc=DEFAULT_CC, flags=DEFAULT_FLAGS, prebuilt=False, aliases=None):
    if isinstance(aliases, str):
        aliases = json.loads(open(aliases).read()) if aliases.strip().startswith("{") else load_aliases()
    if addr not in STARTS:
        raise ValueError("check requires an exact function start: %08X" % addr)
    if md is None:
        raise RuntimeError("Disassembly requires capstone; install requirements.txt")
    with file_lock(os.path.join(ROOT, "logs", "compiler.lock")):
        return _cmd_check(src, addr, sym, cc, flags, prebuilt, aliases)


def _cmd_check(src, addr, sym, cc, flags, prebuilt, aliases=None):
    load_code()
    s, e = func_range(addr)
    obj = os.path.splitext(src)[0] + ".o"
    if prebuilt:  # the caller already compiled src to obj (e.g. many files in one armcc call)
        if not os.path.exists(obj):
            print("COMPILE ERROR\n(no object)")
            return
    else:
        exe = os.path.join(ROOT, "tools", "armcc", *cc.split("/"), "bin", "armcc.exe")
        # 4.1/b1049 ships a broken Authenticode signature that Windows re-verifies on every launch (serialized, ~4/s);
        # b1049ns is the same exe with the certificate table stripped (code untouched, identical output, verified).
        fast = os.path.join(ROOT, "tools", "armcc", "4.1", "b1049ns", "bin", "armcc.exe")
        if cc == "4.1/b1049" and os.name == "nt" and os.path.exists(fast):
            exe = fast
        if not os.path.exists(exe):
            print("COMPILE ERROR\narmcc not found at %s\n"
                  "Place ARM Compiler 4.1 (build 1049) under tools/armcc/; see README.md 'Requirements'." % exe)
            return
        lang = "--cpp" if src.endswith((".cpp", ".cc")) else "--c99"
        inc = os.path.join(ROOT, "shared", "include")
        args = [exe, "-c", lang] + flags.split() + ["-I", inc, "-o", obj, src]
        if os.name != "nt":
            args = ["wine"] + args  # Linux server: the Windows compiler runs under Wine
        r = subprocess.run(args, capture_output=True, text=True)
        msg = (r.stdout + r.stderr).strip()
        if r.returncode != 0:
            print("COMPILE ERROR\n" + msg)
            return
        if msg:
            print(msg)
    d, secs, syms, rels = parse_elf(obj)
    funcs = [x for x in syms if x["type"] == 2 and x["shndx"] not in (0, 0xFFF1) and x["size"] and "$$" not in x["name"]]
    if sym:
        funcs = [x for x in funcs if sym in x["name"]]
    if not funcs:
        print("no matching function symbol in object; symbols:", [x["name"] for x in syms if x["type"] == 2])
        return
    e_full = e
    while e - 4 > s and rd32(e - 4) == 0xE1A00000:  # alignment padding before the next function
        e -= 4
    if e < e_full and code_end(s, e)[0] >= e:
        lw = rd32(e - 4)
        if not ((lw & 0x0FFFFFFF) == 0x012FFF1E or (lw & 0x0FFF8000) == 0x08BD8000
                or (lw & 0x0F000000) == 0x0A000000 or (lw & 0x0FFFF000) == 0x059FF000) or (lw >> 28) != 0xE:
            e += 4  # the linker turned a final tail call "b next_function" into a NOP: it belongs to us
    target = CODE[s - TA:e - TA]

    def compare(f):
        sec = secs[f["shndx"]]
        # the symbol size excludes the literal pool; extend to the next function (or section end)
        fend = min([x["value"] for x in syms if x["shndx"] == f["shndx"] and x["type"] == 2 and x["value"] > f["value"]
                    and "$$" not in x["name"]] + [sec["size"]])
        mine = d[sec["off"] + f["value"]: sec["off"] + fend]
        relmap = {o - f["value"]: (t, n) for o, t, n in rels.get(f["shndx"], []) if f["value"] <= o < fend}
        if len(target) % 4 or len(mine) % 4:
            raise ValueError("comparison requires complete ARM words")
        section_bases = data_section_bases(secs, syms)
        section_bases[f["shndx"]] = s - f["value"]
        n_t, n_m = len(target) // 4, len(mine) // 4
        same = 0
        rows = []
        for i in range(max(n_t, n_m)):
            tw = struct.unpack_from("<I", target, i * 4)[0] if i < n_t else None
            mw = struct.unpack_from("<I", mine, i * 4)[0] if i < n_m else None
            ok = word_matches(mw, tw, relmap.get(i * 4), s + i * 4, section_bases, aliases)
            same += ok
            rows.append((i, tw, mw, ok, relmap.get(i * 4)))
        return same, n_t, n_m, rows, mine, relmap

    # with several functions in the file, compare against the one that matches best
    results = [(compare(f), f) for f in funcs]
    results.sort(key=lambda r: (r[0][0] == max(r[0][1], r[0][2]) and r[0][1] == r[0][2],
                                r[0][0] / max(r[0][1], r[0][2], 1)), reverse=True)
    (same, n_t, n_m, rows, mine, relmap), f = results[0]
    if len(funcs) > 1:
        print(f"{len(funcs)} functions in object, best match is {f['name']} (use --sym to force another)")

    total = max(n_t, n_m)
    pct = 100.0 * same / total if total else 0
    exact = same == total and n_t == n_m

    # alignment-based similarity: insertions/deletions don't wreck everything after them
    ce, tpool = code_end(s, e)
    # switch jump tables after "ldr pc, [pc, rX, lsl #2]" hold absolute addresses (ABS32 in our object)
    jt = set()
    for a in range(s, e, 4):
        if (rd32(a) & 0x0FFFFFF0) == 0x079FF100:
            j = a + 8
            while j < e and s <= rd32(j) < e:
                jt.add(j)
                j += 4

    def tok_t(i):
        a = s + i * 4
        w = rd32(a)
        if a >= ce or a in tpool or a in jt:
            return ("P",)
        if (w >> 25) == 0x7D:
            return ("BR", 0xEB)  # BLX made by the linker counts as BL
        if (w & 0x0E000000) == 0x0A000000:
            return ("BR", w >> 24)
        return w

    def tok_m(i):
        w = struct.unpack_from("<I", mine, i * 4)[0]
        rel = relmap.get(i * 4)
        if rel and rel[0] == 2:
            return ("P",)
        if (w & 0x0E000000) == 0x0A000000:
            return ("BR", w >> 24)
        return w

    tt = [tok_t(i) for i in range(n_t)]
    mt = [tok_m(i) for i in range(n_m)]
    sm = difflib.SequenceMatcher(None, tt, mt, autojunk=False)
    sim = 100.0 if exact else 100.0 * sm.ratio()
    print(f"target func_{s:08X} {len(target)} bytes | yours '{f['name']}' {len(mine)} bytes")
    print(f"RESULT: {'MATCH' if exact else 'NO MATCH'}  {same}/{total} words ({pct:.1f}%)  similarity {sim:.1f}%")

    def dis(w, a):
        if w is None:
            return ""
        l = list(md.disasm(struct.pack("<I", w), a))
        return f"{l[0].mnemonic} {l[0].op_str}" if l else f".word {w:#x}"

    if not exact and n_t == n_m:
        print(f"  {'off':>5}  {'original':38} {'yours':38}")
        for i, tw, mw, ok, rel in rows:
            mark = "  " if ok else "!!"
            r = f" [{rel[1]['name']}; relocation identity not proved]" if rel and not ok else ""
            print(f"{mark}{i * 4:5x}  {dis(tw, s + i * 4):38} {dis(mw, s + i * 4):38}{r}")
    elif not exact:
        print("sizes differ: aligned diff (only changed blocks, 2 lines of context)")
        print(f"  {'orig':>5} {'mine':>5}  {'original':38} {'yours':38}")
        for group in sm.get_grouped_opcodes(2):
            print("  ---")
            for op, a1, a2, b1, b2 in group:
                for k in range(max(a2 - a1, b2 - b1)):
                    ti, mi = a1 + k, b1 + k
                    tw = rd32(s + ti * 4) if ti < a2 else None
                    mw = struct.unpack_from("<I", mine, mi * 4)[0] if mi < b2 else None
                    mark = "  " if op == "equal" else "!!"
                    print(f"{mark}{ti * 4 if tw is not None else '':>5} {mi * 4 if mw is not None else '':>5}  "
                          f"{dis(tw, s + ti * 4):38} {dis(mw, s + mi * 4):38}")
    log = os.path.join(os.path.dirname(os.path.abspath(src)), "check_log.jsonl")
    with open(log, "a") as fh:
        # "end" = the range end used; a check run with an in-memory patched table logs a range that differs
        # from funcs.json, so tools can reject it (make_done.py / auto_harvest.py re-verify against the real table)
        fh.write(json.dumps({"t": time.strftime("%H:%M:%S"), "addr": f"{s:08X}", "end": f"{e_full:08X}",
                             "src": os.path.basename(src), "pct": round(pct, 1), "sim": round(sim, 1), "match": exact,
                             "cc": cc, "flags": flags}) + "\n")


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        sys.exit(0)
    if a[0] == "rebuild-table":
        build_table()
        print("rebuilt funcs.json")
    elif a[0] == "show":
        cmd_show(int(a[1], 16))
    elif a[0] == "xref":
        cmd_xref(int(a[1], 16))
    elif a[0] == "check":
        kw = {}
        rest = a[3:]
        while rest:
            k, v = rest[0], rest[1]
            kw[k.lstrip("-")] = v
            rest = rest[2:]
        cmd_check(a[1], int(a[2], 16), **kw)
