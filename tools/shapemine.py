#!/usr/bin/env python
"""Systematic shape mining over the matched corpus (automation step 3b).

  python tools/shapemine.py index        build logs/shapemine/ (resumable, needs code.bin)
  python tools/shapemine.py rank [--top N] [--min-files K] [--min-unlock U]
                                         [--sort score|files|unlock] [--focus any|stores] [--json]
  python tools/shapemine.py candidate <id>   full shape spec: examples + unindexed overlap
  python tools/shapemine.py next [--focus any|stores]   best unreported candidate + NEXT:
                                         (default focus=stores: header-shape motifs)
  python tools/shapemine.py reset        clear the reported list

Method: every function start in funcs.json is disassembled and each instruction
is normalized to a motif token (condition stripped, registers -> r, immediates
-> #, PC-relative loads -> POOL, calls -> CALL). All n-grams (n=4,5) of the
token stream form the function's motif set. A cluster is one n-gram together
with its posting lists: matched side = functions with a registered source
(file frequency = distinct source paths), unmatched side = starts with no
source path (the functions a header shape would unlock).

Clusters are ranked by leverage score = file_frequency * unindexed_overlap:
many matched files prove the shape is real and reproducible from C, many
unindexed functions are what promoting it to shared/include/ would unlock.
`candidate` emits a paste-ready draft spec (logs/shapemine/candidates/<id>.h)
with example sources to derive the struct/inline shape from.

State (gitignored, regenerable): logs/shapemine/{fn.jsonl,sigs.json,motifs.json,
reported.json,candidates/}.
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import atomic_write, file_lock, read_json, write_json  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "logs", "shapemine")
FN_LOG = os.path.join(STATE, "fn.jsonl")
SIGS = os.path.join(STATE, "sigs.json")
MOTIFS = os.path.join(STATE, "motifs.json")
REPORTED = os.path.join(STATE, "reported.json")
CAND_DIR = os.path.join(STATE, "candidates")

NGRAMS = (4, 5)

# ---------------------------------------------------------------- tokens (pure)

_REG = re.compile(r"\br\d+\b|\bsp\b")
_IMM = re.compile(r"#-?0x[0-9a-fA-F]+|#-?\d+")
_COND = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
         "hi", "ls", "ge", "lt", "gt", "le")


def _strip_cond(m):
    """capstone spells conditions as a suffix (ldrne, beq, popeq)."""
    for c in sorted(_COND, key=len, reverse=True):
        if m.endswith(c) and len(m) > len(c):
            return m[:-len(c)]
    return m


def token_of(mnemonic, op_str):
    """Normalize one instruction to a motif token.

    Conditions are stripped; registers collapse to r; immediates to #;
    PC-relative pool loads become POOL; direct calls become CALL. Shifts and
    addressing modes survive as structure (lsl #, [r, #]!, etc).
    """
    m = _strip_cond(mnemonic.split(".")[0])
    if m in ("bl", "blx") and op_str.startswith("#"):
        return "bl CALL"
    if m in ("ldr", "vldr") and "[pc" in op_str:
        return m + " r, POOL"
    op = _REG.sub("r", op_str)
    op = _IMM.sub("#", op)
    return m + " " + op if op else m


def ngrams(tokens, ns=NGRAMS):
    """All n-gram signature strings of a token stream (deduped, order kept)."""
    out, seen = [], set()
    for n in ns:
        for i in range(len(tokens) - n + 1):
            sig = " ; ".join(tokens[i:i + n])
            if sig not in seen:
                seen.add(sig)
                out.append(sig)
    return out


def motif_id(sig):
    return hashlib.blake2b(sig.encode("utf-8"), digest_size=8).hexdigest()


# ------------------------------------------------------------- binary indexing

def func_tokens(addr):
    """Motif tokens of one function's instruction stream (pool excluded)."""
    import fn
    s, e = fn.func_range(addr)
    ce, _pool = fn.code_end(s, e)
    toks = []
    for a in range(s, ce, 4):
        ins = fn.dis1(a)
        if ins is None:
            continue
        toks.append(token_of(ins.mnemonic, ins.op_str))
    return toks


def cmd_index(args):
    import fn
    os.makedirs(STATE, exist_ok=True)
    done = set()
    if os.path.exists(FN_LOG):
        with open(FN_LOG, encoding="utf-8") as fh:
            for line in fh:
                try:
                    done.add(json.loads(line)["addr"])
                except (ValueError, KeyError):
                    pass
    sigs = read_json(SIGS) if os.path.exists(SIGS) else {}
    starts = [a for a in fn.STARTS if "%08X" % a not in done]
    total = len(starts)
    print("indexing %d remaining starts (%d already done)" % (total, len(done)), flush=True)
    out = open(FN_LOG, "a", encoding="utf-8")
    try:
        for i, addr in enumerate(starts):
            key = "%08X" % addr
            sigs_new = ngrams(func_tokens(addr))
            ids = sorted({motif_id(s) for s in sigs_new})
            for s in sigs_new:
                sigs[motif_id(s)] = s
            out.write(json.dumps({"addr": key, "motifs": ids}) + "\n")
            if (i + 1) % 500 == 0:
                out.flush()
                write_json(SIGS, sigs)
                print("  %d/%d" % (i + 1, total), flush=True)
    finally:
        out.close()
        write_json(SIGS, sigs)
    # aggregation cache is stale now
    if os.path.exists(MOTIFS):
        os.unlink(MOTIFS)
    print("NEXT  python tools/shapemine.py rank --top 30")


# ------------------------------------------------------------- aggregation

def aggregate(force=False):
    """motif id -> {sig, m:[addr], u:[addr]}; cached in motifs.json keyed by line count."""
    if not os.path.exists(FN_LOG):
        sys.exit("no index; run: python tools/shapemine.py index")
    n_lines = sum(1 for _ in open(FN_LOG, encoding="utf-8"))
    if not force and os.path.exists(MOTIFS):
        cached = read_json(MOTIFS)
        if cached.get("lines") == n_lines:
            return cached["motifs"]
    functions = read_json(os.path.join(ROOT, "functions.json"))
    sigs = read_json(SIGS) if os.path.exists(SIGS) else {}
    motifs = {}
    with open(FN_LOG, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            key = rec["addr"]
            ent = functions.get(key) or {}
            side = "m" if ent.get("path") else "u"
            for mid in rec["motifs"]:
                ent2 = motifs.get(mid)
                if ent2 is None:
                    ent2 = motifs[mid] = {"sig": sigs.get(mid, mid), "m": [], "u": []}
                ent2[side].append(key)
    write_json(MOTIFS, {"lines": n_lines, "motifs": motifs})
    return motifs


_STORE = re.compile(r"\b(str|strb|strh|strd|stm) ")


def focus_ok(sig, focus):
    """Header-shape filter: 'stores' keeps store-dense, call-free inlined bodies
    (the constructor/setter shapes that become shared/include structs); 'any'
    keeps every motif, including control-flow boilerplate."""
    if focus == "any":
        return True
    if focus == "stores":
        return bool(_STORE.search(sig)) and "bl CALL" not in sig
    raise ValueError("unknown focus %r" % focus)


def rank_clusters(motifs, min_files=5, min_unlock=3, sort="score", top=30, focus="any"):
    """Rank clusters by leverage; pure function (unit-tested offline)."""
    functions = read_json(os.path.join(ROOT, "functions.json"))
    rows = []
    for mid, ent in motifs.items():
        if not focus_ok(ent["sig"], focus):
            continue
        files = sorted({functions[a]["path"] for a in ent["m"] if a in functions and functions[a].get("path")})
        if len(files) < min_files or len(ent["u"]) < min_unlock:
            continue
        score = len(files) * len(ent["u"])
        rows.append({"id": mid, "sig": ent["sig"], "files": len(files),
                     "funcs_m": len(ent["m"]), "unlock": len(ent["u"]),
                     "score": score, "example_files": files[:3],
                     "example_u": ent["u"][:5]})
    key = {"score": lambda r: -r["score"], "files": lambda r: -r["files"],
           "unlock": lambda r: -r["unlock"]}[sort]
    rows.sort(key=lambda r: (key(r), -r["files"], r["id"]))
    return rows[:top] if top else rows


def cmd_rank(args):
    motifs = aggregate()
    rows = rank_clusters(motifs, args.min_files, args.min_unlock, args.sort, args.top, args.focus)
    if args.json:
        print(json.dumps(rows, indent=1))
        return
    print("%-18s %6s %6s %6s %7s  motif" % ("id", "files", "fm", "unlk", "score"))
    for r in rows:
        print("%-18s %6d %6d %6d %7d  %s" % (r["id"], r["files"], r["funcs_m"],
                                             r["unlock"], r["score"], r["sig"][:110]))
    if rows:
        print("NEXT  python tools/shapemine.py candidate %s" % rows[0]["id"])
    else:
        print("NEXT  lower --min-files/--min-unlock or re-run index")


# ---------------------------------------------------------------- candidates

def candidate_spec(mid, motifs, functions, top_examples=8, top_u=40):
    ent = motifs.get(mid)
    if ent is None:
        sys.exit("unknown motif id %s (see rank)" % mid)
    files = {}
    for a in ent["m"]:
        e = functions.get(a) or {}
        if e.get("path"):
            files.setdefault(e["path"], []).append(a)
    spec = {
        "id": mid, "sig": ent["sig"],
        "matched_files": len(files), "matched_funcs": len(ent["m"]),
        "unindexed_overlap": len(ent["u"]),
        "examples": [{"path": p, "addrs": v[:3]} for p, v in sorted(files.items())[:top_examples]],
        "unindexed_addrs": ent["u"][:top_u],
    }
    return spec


def cmd_candidate(args):
    motifs = aggregate()
    functions = read_json(os.path.join(ROOT, "functions.json"))
    spec = candidate_spec(args.id, motifs, functions)
    os.makedirs(CAND_DIR, exist_ok=True)
    draft = os.path.join(CAND_DIR, "%s.h" % spec["id"])
    lines = [
        "// shape sm_%s" % spec["id"],
        "// mined: %d matched files (%d functions); would unlock ~%d unindexed functions"
        % (spec["matched_files"], spec["matched_funcs"], spec["unindexed_overlap"]),
        "// motif: %s" % spec["sig"],
        "// examples: %s" % ", ".join("%s (%s)" % (e["path"], e["addrs"][0]) for e in spec["examples"]),
        "// derive the struct/inline shape from the examples, place it in",
        "// shared/include/albw_shapes.h, then verify with fn.py check -> RESULT: MATCH",
        "// on 2-3 of the example functions.",
        "",
    ]
    atomic_write(draft, "\n".join(lines))
    print(json.dumps(spec, indent=1) if args.json else
          "shape %s\n  motif:   %s\n  files:   %d matched (%d funcs) -> ~%d unindexed\n  examples: %s\n  unlock:  %s\n  draft:   %s"
          % (spec["id"], spec["sig"], spec["matched_files"], spec["matched_funcs"],
             spec["unindexed_overlap"],
             "; ".join("%s@%s" % (e["path"], e["addrs"][0]) for e in spec["examples"]),
             " ".join(spec["unindexed_addrs"]), draft))
    print("NEXT  read the example sources, promote the shape into shared/include/albw_shapes.h,")
    print("     then re-verify examples (fn.py check) and register matches (worklist.py register)")


def cmd_next(args):
    motifs = aggregate()
    reported = read_json(REPORTED) if os.path.exists(REPORTED) else []
    rows = rank_clusters(motifs, args.min_files, args.min_unlock, "score", 0, args.focus)
    todo = [r for r in rows if r["id"] not in set(reported)]
    if not todo:
        print("all ranked candidates reported; NEXT  python tools/shapemine.py reset  # or lower --min-files")
        return
    r = todo[0]
    with file_lock(os.path.join(STATE, "shapemine.lock")):
        reported = read_json(REPORTED) if os.path.exists(REPORTED) else []
        if r["id"] not in reported:
            reported.append(r["id"])
            write_json(REPORTED, reported)
    print("next shape candidate: %s" % r["id"])
    print("  motif:  %s" % r["sig"])
    print("  leverage: %d matched files x %d unindexed functions = %d" % (r["files"], r["unlock"], r["score"]))
    print("  examples: %s" % "; ".join(r["example_files"]))
    print("  unlock sample: %s" % " ".join(r["example_u"]))
    print("NEXT  python tools/shapemine.py candidate %s" % r["id"])


def cmd_reset(args):
    if os.path.exists(REPORTED):
        os.unlink(REPORTED)
    print("reported list cleared; NEXT  python tools/shapemine.py next")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("index")
    p.set_defaults(fn=cmd_index)
    p = sub.add_parser("rank")
    p.add_argument("--top", type=int, default=30)
    p.add_argument("--min-files", type=int, default=5)
    p.add_argument("--min-unlock", type=int, default=3)
    p.add_argument("--sort", choices=("score", "files", "unlock"), default="score")
    p.add_argument("--focus", choices=("any", "stores"), default="any",
                   help="stores = store-dense call-free motifs (header shapes)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_rank)
    p = sub.add_parser("candidate")
    p.add_argument("id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_candidate)
    p = sub.add_parser("next")
    p.add_argument("--min-files", type=int, default=5)
    p.add_argument("--min-unlock", type=int, default=3)
    p.add_argument("--focus", choices=("any", "stores"), default="stores")
    p.set_defaults(fn=cmd_next)
    p = sub.add_parser("reset")
    p.set_defaults(fn=cmd_reset)
    args = ap.parse_args()
    os.makedirs(STATE, exist_ok=True)
    args.fn(args)


if __name__ == "__main__":
    main()
