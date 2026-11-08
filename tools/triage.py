"""Triage unindexed functions: classify asm/CRT/linker artifacts vs armcc-producible candidates.

  python tools/triage.py [--region 0x100000-0x200000] [--out logs/triage]
  python tools/triage.py --hints          # auto-inject forwarder/veneer hints
                                        # into shared/extra_starts.txt
  python tools/triage.py --hints --dry-run

Classification signatures come from docs/LESSONS.md open-problem work:
  svc      - kernel SVC wrappers (armcc's __svc is call-shaped, never frameless)
  mrc_mcr  - p15 coprocessor ops (TLS asm; armcc 4.1 has no __mrc intrinsic)
  veneer   - "ldr pc,[pc,#imm]" linker veneers (not source functions)
  atomic   - ldrex/strex (some are honest matches, some are asm: needs manual look)
  pad_tail - ends in alignment padding with no terminator (cross-function fall-through)
  candidate- everything else: worth a source attempt, sorted smallest-first
"""
import os
import struct
import sys

from common import atomic_write, file_lock, load_binary, read_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLASSES = ("svc", "mrc_mcr", "veneer", "atomic", "pad_tail", "candidate")
TA, TS = 0x100000, 5841180


def classify(words):
    has_term = False
    for w in words:
        if (w >> 24) == 0xEF:
            return "svc"
        if (w & 0x0F000000) == 0x0E000000 and ((w >> 8) & 0xF) == 0xF:
            return "mrc_mcr"
        if (w & 0xFFFFF000) == 0xE51FF000:
            return "veneer"
        if (w & 0x0FF00FF0) in (0x01900F90, 0x01800F90):
            return "atomic"
        # terminators: bx lr (E12FFF1E), pop {...,pc}, unconditional b, ldmia pc
        if w == 0xE12FFF1E or (w & 0x0FFF8000) == 0x08BD8000 \
           or (w & 0x0F000000) == 0x0A000000 or (w & 0x0FFF0000) == 0x089D0000:
            has_term = True
    if not has_term and len(words) >= 2 and words[-1] == 0xE1A00000:
        return "pad_tail"
    return "candidate"


def _is_end(w):
    return (w == 0xE12FFF1E or (w & 0xFFFF8000) == 0xE8BD8000 or w == 0xE49DF004
            or (w & 0xFF000000) == 0xEA000000 or (w & 0xFFFFFFF0) == 0xE12FFF10)


def _looks_like_fn(words, i):
    for k in range(4):
        if i + k >= len(words):
            break
        x = words[i + k]
        if (x & 0xFFFF0000) in (0xE92D0000, 0xE24D0000) or x in (0xE49DF004, 0xE12FFF1E):
            return True
    return False


def find_forwarder_hints():
    """Detect unreferenced function starts reached only via linker artifacts:

    - NOPped tail calls: word at F-4 is 0xE1A00000 (mov r0,r0 = NOP) and the
      word at F-8 is a terminator — the linker replaced `b F` with a NOP,
      so F has no BL/pointer reference but is a real function start.
    - Veneers: `ldr pc,[pc,#imm]` (E51FFxxx) whose pool word targets F —
      a linker veneer, not a source function; the TARGET may still be an
      unreferenced real start.
    Returns (nopped_targets, veneer_targets) as sorted address lists.
    """
    code = load_binary(os.path.join(ROOT, "code.bin"))
    words = struct.unpack("<%dI" % (len(code) // 4), code)
    funcs = read_json(os.path.join(ROOT, "funcs.json"))
    starts = funcs["starts"]
    bl = set(funcs["bl"])
    ptr = set(funcs["ptr"])
    extra_path = os.path.join(ROOT, "shared", "extra_starts.txt")
    extra = set()
    if os.path.exists(extra_path):
        extra = {int(l.split()[0], 16) for l in open(extra_path)
                 if l.strip() and not l.startswith("#")}

    nopped, veneers = [], []
    for i, x in enumerate(words):
        if (x & 0xFFFFF000) == 0xE51FF000:  # ldr pc,[pc,#imm] veneer
            la = TA + i * 4 + 8 + (x & 0xFFF)
            if TA <= la <= TA + len(code) - 4:
                t = struct.unpack_from("<I", code, la - TA)[0]
                if TA <= t < TA + len(code):
                    veneers.append(t)
    veneer_set = set(veneers)
    for s in starts:
        if s in bl or s in ptr or s in extra:
            continue
        i = (s - TA) // 4
        if i >= 2 and words[i - 1] == 0xE1A00000 and _is_end(words[i - 2]) \
                and _looks_like_fn(words, i) and words[i] >> 24 != 0xEF:
            nopped.append(s)  # skip svc stubs (neg-svc-stub class)
        elif s in veneer_set and _looks_like_fn(words, i) and words[i] >> 24 != 0xEF:
            nopped.append(s)  # veneer target with no direct ref
    return sorted(set(nopped)), sorted(veneer_set)


def inject_hints(dry_run=False):
    """Append auto-detected forwarder/veneer targets to extra_starts.txt."""
    nopped, veneers = find_forwarder_hints()
    path = os.path.join(ROOT, "shared", "extra_starts.txt")
    existing = set()
    lines = []
    if os.path.exists(path):
        lines = [l for l in open(path) if l.strip()]
        existing = {int(l.split()[0], 16) for l in lines if not l.startswith("#")}
    new = [s for s in nopped if s not in existing]
    if not new:
        print("no new forwarder hints (all %d already in extra_starts.txt)" % len(nopped))
        return 0
    note = "auto: triage.py --hints (NOPped tail-call/veneer target, unreferenced start)"
    add = "".join("%08X %s\n" % (s, note) for s in new)
    print("%s %d new hint(s):" % ("would add" if dry_run else "added", len(new)))
    for s in new:
        print("  %08X" % s)
    if not dry_run:
        with file_lock(path + ".lock"):
            with open(path, "a") as f:
                f.write(add)
    return len(new)


def main():
    if "--hints" in sys.argv:
        sys.exit(0 if inject_hints(dry_run="--dry-run" in sys.argv) >= 0 else 1)
    lo = hi = None
    if "--region" in sys.argv:
        a, b = sys.argv[sys.argv.index("--region") + 1].split("-")
        lo, hi = int(a, 16), int(b, 16)
    outdir = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else os.path.join(ROOT, "logs", "triage")

    code = load_binary(os.path.join(ROOT, "code.bin"))
    starts = read_json(os.path.join(ROOT, "funcs.json"))["starts"]
    indexed = set(read_json(os.path.join(ROOT, "functions.json")))
    os.makedirs(outdir, exist_ok=True)

    buckets = {name: [] for name in CLASSES}
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else TA + TS
        if s in (0x10BFFC,):  # 0x10BFFC exists only as 0x10BFD4's fall-through pad
            continue
        if lo is not None and not (lo <= s < hi):
            continue
        if f"{s:08X}" in indexed:
            continue
        n = (e - s) // 4
        words = struct.unpack_from("<%dI" % n, code, s - TA)
        buckets.setdefault(classify(list(words)), []).append((s, e - s))

    with file_lock(os.path.join(outdir, "write.lock")):
        for cls, lst in sorted(buckets.items()):
            path = os.path.join(outdir, "unindexed_%s.txt" % cls)
            atomic_write(path, "".join("%08X %d\n" % (s, size)
                                     for s, size in sorted(lst, key=lambda x: x[1])))
            smallest = min((size for _, size in lst), default=0)
            print("%-9s %5d  (smallest %d B)  -> %s" % (cls, len(lst), smallest, path))
    total = sum(len(v) for v in buckets.values())
    print("%-9s %5d" % ("TOTAL", total))


if __name__ == "__main__":
    main()
