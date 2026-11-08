"""Skeleton synthesizer (automation step 3).

  python tools/synth.py 0xADDR          synthesize a starting skeleton + sweep spec
  python tools/synth.py 0xADDR --json   machine-readable result

Pipeline: negative-recipe check (refuse = defer) -> store-map skeleton ->
sweep.py spec at logs/synth/<addr>/spec.py. The skeleton is a GUESS: the
refiner (phase 4) is the loop that closes the remaining bytes; the only
registration gate stays fn.py check -> RESULT: MATCH.
"""
import json
import os
import re
import sys

import fn

ROOT = fn.ROOT
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from recipes import load as load_recipes

OUT = os.path.join(ROOT, "logs", "synth")


# ---------------------------------------------------------------- disasm view

def view(addr):
    """Mnemonic view of the function with pool refs and calls annotated."""
    s, e = fn.func_range(addr)
    ins = []
    for a in range(s, e, 4):
        w = fn.rd32(a)
        i = fn.dis1(a)
        if i is None:
            continue
        m = i.mnemonic.split(".")[0]
        if m in ("ldr", "vldr") and "pc" in i.op_str:
            mm = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", i.op_str)
            la = a + 8 + int(mm.group(1), 0)
            ins.append((m, "POOL %08X" % fn.rd32(la & ~3)))
            continue
        if m in ("bl", "blx") and i.op_str.startswith("#"):
            ins.append(("CALL", "CALL %08X" % int(i.op_str[1:], 0)))
            continue
        if m == "svc":
            ins.append((m, i.op_str))
            continue
        if m == "bx" or (m == "mov" and i.op_str == "r0, r0"):
            ins.append((m, i.op_str))
            continue
        ins.append((m, i.op_str))
    POOL_ADDR[0] = addr  # so check_negative can count raw pool words past body
    return s, e, ins


# ------------------------------------------------------------- class matcher

def classify(ins):
    """Map instruction view to a synthesis class or None (defer)."""
    ms = [m for m, _ in ins]
    if any(m in ("svc", "mrc", "mcr") for m in ms):
        return None
    if ms and ms[0] == "ldr" and ins[0][1].startswith("POOL") and "pc, #-4" in str(ins):
        return None
    if "vmov" in ms and "vcvt" in ms:
        return None
    if any(m.startswith("v") for m in ms):
        return None  # VFP families handled by recipes until synth learns them
    if "ldrex" in ms or "strex" in ms:
        return None
    calls = [o for m, o in ins if m == "CALL"]
    # single-call wrapper: push {r4,lr}; mov r4,r0; bl; ... pop {r4,pc}
    if len(calls) == 1 and ms and ms[0] == "push" and ms[-1] == "pop":
        return "wrapper"
    # single tail call: b target (conditional-branch forms stripped below)
    if len(calls) == 0 and len(ms) >= 2 and ms[-2].startswith("b"):
        return "thunk"
    # pure store/init/setter bodies
    if calls == [] and set(ms) - {"mov", "add", "str", "strb", "strh", "strd", "stm", "ldr", "ldm", "cmp", "rsb", "mul", "orr", "and", "lsl", "lsr", "asr", "b", "bx", "bxeq", "bxne", "sub", "eor"} == set():
        if not any(m.startswith("st") for m in ms):
            return None  # pure loads: a getter/table-lookup, no skeleton form yet
        return "stores"
    if len(calls) == 1:
        return "call+stores"
    return None


# ---------------------------------------------------------------- generators

def _off_expr(off):
    # a store offset can be negative (e.g. base r4 = r0 - 0xb4); C has no 0x-b4
    return "(char*)self + 0x%x" % off if off >= 0 else "(char*)self - 0x%x" % -off


def skeleton_from_stores(addr, ins):
    """Best-effort setter/ctor lines from str-patterns against self chain."""
    body = []
    bases = {0: 0}
    for m, o in ins:
        mm = re.fullmatch(r"(r\d+), (r\d+)", o)
        if m == "mov" and mm:
            if int(mm.group(2)[1:]) in bases:
                bases[int(mm.group(1)[1:])] = bases[int(mm.group(2)[1:])]
            continue
        mm = re.fullmatch(r"(r\d+), (r\d+), #?(0x[0-9a-f]+|\d+)", o)
        if m == "add" and mm and int(mm.group(2)[1:]) in bases:
            bases[int(mm.group(1)[1:])] = bases[int(mm.group(2)[1:])] + int(mm.group(3), 0)
            continue
        mm = re.fullmatch(r"(r\d+|ip), (r\d+|ip), \[(r\d+|sp|ip)(?:, #?(-?(?:0x[0-9a-f]+|\d+)))?\](!?)", o)
        if m == "strd" and mm and mm.group(3) not in ("sp", "ip"):
            b = bases.get(int(mm.group(3)[1:]))
            if b is None:
                continue
            off = b + int(mm.group(4) or "0", 0)
            for k in (0, 1):
                v = mm.group(1 + k)
                val = "self" if v == "r0" else ("p" + v[1] if v in ("r1", "r2", "r3") else "p1")
                body.append("    *(u32*)(%s) = %s;" % (_off_expr(off + 4 * k), val))
            continue
        mm = re.fullmatch(r"(r\d+|ip), \[(r\d+|sp|ip)(?:, #?(-?(?:0x[0-9a-f]+|\d+)))?\](!?)", o)
        if m.startswith("str") and m != "stm" and mm and mm.group(2) not in ("sp", "ip"):
            b = bases.get(int(mm.group(2)[1:]))
            if b is None:
                continue
            off = b + (int(mm.group(3) or "0", 0))
            v = mm.group(1)
            cast = {"strb": "u8*", "strh": "u16*"}.get(m, "u32*")
            # value guess: r0=r0 (self), r1/r2/r3 = params, immediate seen earlier?
            if v == "r0":
                val = "self"
            elif v in ("r1", "r2", "r3"):
                val = "p" + v[1]
            else:
                val = "p1"  # placeholder; the refiner's VALUES wave substitutes
            # narrow stores need an integer value: a pointer stored through u8*/u16*
            # is a compile error (armcc #513); truncate the guess to the width.
            if cast != "u32*" and not val.isdigit():
                val = "(u32)%s" % val
            body.append("    *(%s)(%s) = %s;" % (cast, _off_expr(off), val))
            continue
        mm = re.fullmatch(r"(r\d+|sp|ip)(!)?, \{(.+)\}", o)
        if m == "stm" and mm and mm.group(1) not in ("sp", "ip"):
            b = bases.get(int(mm.group(1)[1:]))
            if b is None:
                continue
            regs = re.findall(r"r(\d+)", mm.group(3))
            for k, r in enumerate(regs):
                off = b + 4 * k
                if r == "0":
                    val = "self"
                elif r in ("1", "2", "3"):
                    val = "p" + r
                else:
                    val = "p1"  # placeholder; the refiner's VALUES wave substitutes
                body.append("    *(u32*)(%s) = %s;" % (_off_expr(off), val))
            if mm.group(2):  # writeback: the base advances for later stores
                bases[int(mm.group(1)[1:])] = b + 4 * len(regs)
    return body


def skeleton(addr, cls, ins):
    if cls == "wrapper":
        # push {r4,lr}; mov r4,r0; bl helper; mov r0,r4; pop {r4,pc}
        target = [o for m, o in ins if m == "CALL"][0].split()[1]
        return ("// wrapper: forwards self, returns self\n"
                "extern void func_%s(void*);\n\n"
                "void* func_%08X(void* self) {\n"
                "    func_%s(self);\n"
                "    return self;\n"
                "}\n" % (target, addr, target))
    if cls == "thunk":
        # b target with arg-preserving regs
        bs = [o for m, o in ins if m == "b" and o.startswith("#")]
        tgt = bs[-1].split()[1] if bs and len(bs[-1].split()) > 1 else None
        if not tgt:
            return None
        tgt = re.sub(r"[^0-9a-fA-Fx]", "", tgt)
        return ("// tail thunk\nextern void func_%s(u32, u32, u32, u32);\n\n"
                "void func_%08X(u32 a, u32 b, u32 c, u32 d) {\n"
                "    func_%s(a, b, c, d);\n"
                "}\n" % (tgt, addr, tgt))
    if cls in ("stores", "call+stores"):
        lines = skeleton_from_stores(addr, ins)
        head = ""
        if cls == "call+stores":
            t = [o for m, o in ins if m == "CALL"][0].split()[1]
            head = "extern void func_%s(void*);\n\n" % t
            lines = ["    func_%s(self);" % t] + lines
        return (head +
                "void func_%08X(void* self, u32 p1, u32 p2, u32 p3) {\n"
                % addr + "\n".join(lines) + "\n}\n")
    return None


def sweep_spec(addr, cls):
    return f'''"""Auto-generated sweep spec for 0x{addr:08X} (class {cls})."""
TEMPLATE = """// skeleton from synth
typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned short u16;
extern void helper(void*);
{__import__("open").read(__file__)}
"""
'''


# ------------------------------------------------------------------- main

def check_negative(ins):
    """Hard-skip shapes from the negative recipes (ids mirror
    shared/recipes.json; keep both in sync — these are checked before any
    compile budget is spent)."""
    text = "; ".join(m + " " + o for m, o in ins).lower()
    ms = [m for m, _ in ins]

    def push_r0_lr():
        # neg-armlib-push-r0lr: push {r0,lr} ... pop {r0,pc} — armlib asm
        # idiom; armcc C never emits it (r4 or tail-call in every variant)
        texts = [o for m, o in ins]
        return any(m == "push" and "r0" in o and "lr" in o for m, o in ins) \
            and any(m == "pop" and "r0" in o and "pc" in o for m, o in ins)

    def lr_bulk_data():
        # neg-lr-bulk-data: lr as fill data (mov lr,rX then lr in a stm list)
        for i, (m, o) in enumerate(ins):
            if m == "mov" and re.fullmatch(r"lr, r\d+", o):
                return any(m2.startswith("stm") and "lr" in o2 for m2, o2 in ins[i + 1:])
        return False

    def vfp_wb_dead():
        # neg-vfp-wb-unconditional: vldmia rN! writeback whose pointer is
        # never reused afterwards (00115234: unproducible from C)
        for i, (m, o) in enumerate(ins):
            if m.startswith("vldmia") and "!" in o:
                reg = o.split()[0]
                later = "; ".join(o2 for _, o2 in ins[i + 1:])
                if reg not in later:
                    return True
        return False

    def if_converted_guard_chain():
        # neg-if-converted-guard-chain: a null-check chain emitted as
        # conditional loads/compares (ldrne/cmpne/ldrbne) instead of
        # per-check branches (004A523C, 003F6F84). armcc b1049 from our
        # C forms always picks the branchy form; the if-converted target
        # shape is a hard skip.
        return any(m in ("ldrne", "cmpne", "ldrbne", "ldmne", "strne")
                   for m, _ in ins)

    def bool_materialized_guard():
        # neg-bool-materialized-guard: guard condition materialized to
        # 0/1 (movne rX,#0; moveq rX,#1) then tested with teq rX,#1
        # (00519B4C, 005CBE9C). Every plain C form folds to a direct
        # branch off cmpeq under armcc b1049.
        has_mat = any(m == "mov" and re.fullmatch(r"(ne|eq)", "") for m, _ in ins)
        movne0 = any(m == "movne" and re.fullmatch(r"r\d+, #0", o) for m, o in ins)
        moveq1 = any(m == "moveq" and re.fullmatch(r"r\d+, #1", o) for m, o in ins)
        teq1 = any(m == "teq" and re.fullmatch(r"r\d+, #1", o) for m, o in ins)
        return movne0 and moveq1 and teq1

    def fam_sti_third_pool_word():
        # neg-fam-sti-third-pool-word: fam_sti static-init shape (strd of
        # -1 pair + stm zero pair + value store) whose literal pool holds
        # a THIRD word beyond the matched twins' two pool words
        # (0059F7B8/005A8AA0 carry 0xffffffff; twins 005934D4/005931E8/
        # 005A5B48 have two). The extra pooled word is a TU-sibling
        # constant armcc placed in this function's pool; no C construct
        # we tried materializes it. Pool words past the body decode as
        # garbage mnemonics (e.g. rsbseq) in the view, so count raw words.
        addr = POOL_ADDR[0]
        if addr is None or "strd" not in ms:
            return False
        s, e = fn.func_range(addr)
        # body = instructions up to and including the final bx lr / pop pc;
        # pool = remaining words of the function range
        body_end = None
        for a in range(s, e, 4):
            i = fn.dis1(a)
            if i is None:
                break
            m = i.mnemonic.split(".")[0]
            if m == "bx" and "lr" in i.op_str:
                body_end = a + 4
                break
            if m == "pop" and "pc" in i.op_str:
                body_end = a + 4
                break
        if body_end is None:
            return False
        pool_words = (e - body_end) // 4
        return pool_words >= 3

    def stack_arg_frame_copy():
        # neg-stack-arg-frame-copy: sub sp,#N frame plus caller stack
        # args reloaded via add lr,sp,#k; ldm lr,{...} and a by-value
        # stack arg copied into the local frame with stm sp,{...}
        # (003D3658, 002E284C, 00502F8C). The local copy is DCE'd by
        # armcc from every C form we tried.
        has_sub_sp = any(m == "sub" and o.startswith("sp,") for m, o in ins)
        has_ldm_lr = any(m.startswith("ldm") and o.startswith("lr,") for m, o in ins)
        has_stm_sp = any(m.startswith("stm") and o.startswith("sp,") for m, o in ins)
        return has_sub_sp and has_ldm_lr and has_stm_sp

    NEG = {
        "neg-svc-stub":      lambda: "svc" in text,
        "neg-mrc-mcr":       lambda: any(m in ("mrc", "mcr") for m, _ in ins),
        "neg-veneer":        lambda: text.startswith("ldr") and "pc, #-4" in text and "pool" in text.split(";", 1)[0],
        "neg-f2uiz-s2":      lambda: "vmov" in text and "vcvt" in text,
        "neg-vfp-wb-unconditional": vfp_wb_dead,
        "neg-guarded-vfp-branch": lambda: (
            len(ins) > 2 and ins[0][0] == "cmp" and ins[1][0].startswith("bx")
            and any(m.startswith("v") for m in ms[2:])),
        "neg-armlib-push-r0lr": push_r0_lr,
        "neg-lr-bulk-data": lr_bulk_data,
        "neg-if-converted-guard-chain": if_converted_guard_chain,
        "neg-bool-materialized-guard": bool_materialized_guard,
        "neg-stack-arg-frame-copy": stack_arg_frame_copy,
        "neg-fam-sti-third-pool-word": fam_sti_third_pool_word,
    }
    for rid, test in NEG.items():
        if test():
            return rid
    return None


# module-level scratch so check_negative can see the address of the function
# whose instruction list it was given (pool words live past the body end)
POOL_ADDR = [None]


def main():
    addr = int(sys.argv[1], 16) if len(sys.argv) > 1 else None
    as_json = "--json" in sys.argv
    s, e, ins = view(addr)
    neg = check_negative(ins)
    cls = classify(ins)
    res = {
        "addr": "%08X" % addr,
        "size": e - s,
        "class": cls,
        "negative": neg,
        "path": None,
        "spec": None,
    }
    if neg is None and cls:
        os.makedirs(OUT, exist_ok=True)
        src = skeleton(addr, cls, ins)
        if src:
            p = os.path.join(OUT, "func_%08X.c" % addr)
            open(p, "w").write(src)
            res["path"] = p
    if as_json:
        print(json.dumps(res))
    else:
        print("func_%s  %d bytes" % (res["addr"], res["size"]))
        if neg:
            print("DEFER  negative recipe: %s" % neg)
        elif cls:
            print("class:  %s" % cls)
            print("path:   %s" % res["path"])
            print("NEXT    python tools/refine.py 0x%s --budget 60" % res["addr"])
        else:
            print("DEFER  no synthesis class matched (manual review)")
    return res


if __name__ == "__main__":
    main()
