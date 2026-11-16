#!/usr/bin/env python
"""Re-harvest after every admitted shape batch (automation step 5b).

  python tools/reharvest.py shapes                    PASS shapes + verified sites
  python tools/reharvest.py targets <shape> [--top N] unindexed family members, ranked
  python tools/reharvest.py run <shape> [--limit M] [--budget B]   refine+register
  python tools/reharvest.py next [--limit M] [--budget B]           loop: next unharvested shape

Why: each shape admitted to shared/include/albw_shapes.h changes what dna
twins and synth skeletons predict — a twin whose source now uses the header
shape compiles correctly where it used to be the "wrong construct". Twins
unlock twins (the Nov 2-4 batches were this effect at instruction level;
this repeats it at header level).

How targets are found: a shape's binary signature is the set of shapemine
n-gram motifs present in >= 3 of its verified call sites
(shared/shape_verification.json); every unindexed function containing any of
those motifs (logs/shapemine/) is a family member, ranked by how many of the
shape's motifs it contains. `run` refines each target from its dna twin
(refine --start auto) and registers matches with worklist.py register —
nothing registers without fn.py check RESULT: MATCH.

State: logs/reharvest/{state.json,<shape>.jsonl} (gitignored, resumable).
"""
import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import file_lock, read_json, write_json  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "logs", "reharvest")
STATE_FILE = os.path.join(STATE, "state.json")
REPORT = os.path.join(ROOT, "shared", "shape_verification.json")
SHAPEMINE = os.path.join(ROOT, "logs", "shapemine")
MIN_SITE_MOTIFS = 3
# motif-signature threshold: motifs must appear in at least this many of the
# shape's verified sites (never more than the site count); targeting heuristic
# only — the oracle decides what registers
SIGNATURE_MIN = 2


def load_state():
    if os.path.exists(STATE_FILE):
        return read_json(STATE_FILE)
    return {"harvested": {}, "attempted": {}}


def save_state(state):
    write_json(STATE_FILE, state)


def shape_sites(shape):
    """Verified (MATCH, honest, trick-free) addrs of a shape from the report."""
    report = read_json(REPORT)
    ent = report.get("shapes", {}).get(shape)
    if not ent:
        return []
    return [s["addr"] for s in ent.get("sites", [])
            if s.get("check") == "MATCH" and s.get("status") == "honest" and not s.get("tricks")]


def fn_motifs():
    """addr -> set of shapemine motif ids (from the index log)."""
    path = os.path.join(SHAPEMINE, "fn.jsonl")
    out = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                    out[rec["addr"]] = set(rec["motifs"])
                except (ValueError, KeyError):
                    pass
    return out


def shape_motif_signature(shape, motifs_by_addr, min_sites=None):
    """Motif ids present in >= min_sites verified sites of the shape."""
    sites = shape_sites(shape)
    if min_sites is None:
        min_sites = max(SIGNATURE_MIN, min(MIN_SITE_MOTIFS, len(sites)))
    counts = {}
    for a in sites:
        for mid in motifs_by_addr.get(a, ()):
            counts[mid] = counts.get(mid, 0) + 1
    return {mid for mid, n in counts.items() if n >= min_sites}, sites


def ops_twin_targets(shape):
    """Unindexed functions whose exact dna ops-sequence matches a registered
    verified site of the shape — the twin-sweep half of family targeting.
    Offline; empty when the dna index is not built."""
    import dna
    if not os.path.exists(dna.DNA_FILE):
        return []
    functions = read_json(os.path.join(ROOT, "functions.json"))
    sites = shape_sites(shape)
    site_paths = {functions[a]["path"] for a in sites
                  if a in functions and functions[a].get("path")}
    if not site_paths:
        return []
    idx = dna.load_index()
    ops_hit = set()
    for r in idx:
        ent = functions.get(r["addr"])
        if ent and ent.get("path") in site_paths:
            ops_hit.add(r["ops"])
    return [r["addr"] for r in idx
            if r["ops"] in ops_hit
            and not (functions.get(r["addr"]) or {}).get("path")]


def resolve_targets(shape, top=40, include_ops=True):
    """Unindexed functions exhibiting the shape, ranked by motif overlap
    (ops-twin matches score +10). Pure apart from file reads; unit-tested
    offline with fake state (include_ops=False there).
    """
    motifs_by_addr = fn_motifs()
    sig, sites = shape_motif_signature(shape, motifs_by_addr)
    functions = read_json(os.path.join(ROOT, "functions.json"))
    agg_path = os.path.join(SHAPEMINE, "motifs.json")
    agg = read_json(agg_path) if os.path.exists(agg_path) else {}
    motifs = agg.get("motifs", {})
    score = {}
    for mid in sig:
        for a in motifs.get(mid, {}).get("u", []):
            if a in functions and functions[a].get("path"):
                continue
            score[a] = score.get(a, 0) + 1
    if include_ops:
        for a in ops_twin_targets(shape):
            if a in functions and functions[a].get("path"):
                continue
            score[a] = score.get(a, 0) + 10
    ranked = sorted(score.items(), key=lambda kv: (-kv[1], kv[0]))
    return ranked[:top], sites


def cmd_shapes(args):
    from shape_verify import verdict_of
    report = read_json(REPORT)
    state = load_state()
    for qname, ent in sorted(report.get("shapes", {}).items()):
        verdict = ent.get("verdict") or verdict_of(ent)
        passed = [s["addr"] for s in ent.get("sites", [])
                  if s.get("check") == "MATCH" and s.get("status") == "honest" and not s.get("tricks")]
        mark = "harvested" if qname in state["harvested"] else ""
        print("%-24s %-8s %3d verified sites %s" % (qname, verdict or "?", len(passed), mark))
    print("NEXT  python tools/reharvest.py next")


def cmd_targets(args):
    ranked, sites = resolve_targets(args.shape, args.top)
    print("shape %s: %d verified sites, signature motifs -> %d unindexed targets"
          % (args.shape, len(sites), len(ranked)))
    for a, n in ranked:
        print("  %s  motif-overlap=%d" % (a, n))
    if ranked:
        print("NEXT  python tools/reharvest.py run %s --limit %d" % (args.shape, min(10, len(ranked))))


def cmd_run(args):
    import worklist
    ranked, sites = resolve_targets(args.shape, 10 ** 9)
    targets = [a for a, _ in ranked if a not in load_state()["attempted"]]
    targets = targets[:args.limit]
    if not targets:
        print("no unattempted targets for %s" % args.shape)
        return
    os.makedirs(STATE, exist_ok=True)
    log = open(os.path.join(STATE, "%s.jsonl" % args.shape.replace("::", "_")), "a", buffering=1)
    state = load_state()
    registered = 0
    for key in targets:
        t0 = time.time()
        subprocess.run([sys.executable, "tools/refine.py", "0x" + key,
                        "--budget", str(args.budget), "--start", "auto", "--json"],
                       capture_output=True, text=True, cwd=ROOT, timeout=1200)
        sd = os.path.join(ROOT, "logs", "refine", key)
        sp = os.path.join(sd, "state.json")
        rstate = read_json(sp) if os.path.exists(sp) else {}
        best = rstate.get("best") or {}
        status = rstate.get("status") or ("MATCH" if best.get("match") else "NO")
        line = {"addr": key, "status": status, "used": rstate.get("used"),
                "op": best.get("n_op"), "reg": best.get("n_reg"), "secs": round(time.time() - t0, 1)}
        log.write(json.dumps(line) + "\n")
        print("%s %s used=%s op=%s %.0fs" % (key, status, line["used"], line["op"], line["secs"]), flush=True)
        state["attempted"][key] = {"shape": args.shape, "status": status}
        if status == "MATCH":
            try:
                worklist.register(int(key, 16), as_json=False)
                registered += 1
                print("  REGISTERED %s" % key, flush=True)
            except Exception as exc:
                print("  register failed: %s" % str(exc)[:120], flush=True)
        save_state(state)
    state["harvested"][args.shape] = {"targets": len(targets), "registered": registered,
                                      "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    save_state(state)
    print("harvest %s: %d targets, %d registered" % (args.shape, len(targets), registered))
    print("NEXT  python tools/worklist.py next   # continue the normal loop")


def motif_targets(mid, top=10 ** 9):
    """Unindexed addrs containing a shapemine motif id, ranked by df."""
    functions = read_json(os.path.join(ROOT, "functions.json"))
    agg_path = os.path.join(SHAPEMINE, "motifs.json")
    agg = read_json(agg_path) if os.path.exists(agg_path) else {}
    ent = agg.get("motifs", {}).get(mid)
    if not ent:
        return []
    return [a for a in ent.get("u", [])
            if not (functions.get(a) or {}).get("path")][:top]


def cmd_run_motif(args):
    import worklist
    targets = [a for a in motif_targets(args.motif)
               if a not in load_state()["attempted"]][:args.limit]
    if not targets:
        print("no unattempted targets for motif %s" % args.motif)
        return
    os.makedirs(STATE, exist_ok=True)
    log = open(os.path.join(STATE, "motif_%s.jsonl" % args.motif), "a", buffering=1)
    state = load_state()
    registered = 0
    for key in targets:
        t0 = time.time()
        try:
            subprocess.run([sys.executable, "tools/refine.py", "0x" + key,
                            "--budget", str(args.budget), "--start", "auto", "--json"],
                           capture_output=True, text=True, cwd=ROOT, timeout=1200)
        except subprocess.TimeoutExpired:
            print("%s TIMEOUT (refine >1200s, skipped)" % key, flush=True)
            state["attempted"][key] = {"shape": args.shape, "status": "TIMEOUT"}
            save_state(state)
            continue
        sp = os.path.join(ROOT, "logs", "refine", key, "state.json")
        rstate = read_json(sp) if os.path.exists(sp) else {}
        best = rstate.get("best") or {}
        status = rstate.get("status") or ("MATCH" if best.get("match") else "NO")
        log.write(json.dumps({"addr": key, "status": status, "used": rstate.get("used"),
                              "op": best.get("n_op")}) + "\n")
        print("%s %s used=%s op=%s %.0fs" % (key, status, rstate.get("used"), best.get("n_op"),
                                             time.time() - t0), flush=True)
        state["attempted"][key] = {"motif": args.motif, "status": status}
        if status == "MATCH":
            try:
                worklist.register(int(key, 16), as_json=False)
                registered += 1
                print("  REGISTERED %s" % key, flush=True)
            except Exception as exc:
                print("  register failed: %s" % str(exc)[:120], flush=True)
        save_state(state)
    print("motif %s: %d targets, %d registered" % (args.motif, len(targets), registered))
    print("NEXT  python tools/shapemine.py next   # next mined shape candidate")


def cmd_next(args):
    report = read_json(REPORT)
    state = load_state()
    todo = [q for q, e in sorted(report.get("shapes", {}).items())
            if (e.get("verdict") == "PASS") and q not in state["harvested"]]
    if not todo:
        print("all PASS shapes harvested; NEXT  python tools/worklist.py next")
        return
    shape = todo[0]
    ranked, _ = resolve_targets(shape, 10 ** 9)
    print("next unharvested shape: %s (%d unindexed targets)" % (shape, len(ranked)))
    print("NEXT  python tools/reharvest.py run %s --limit %d --budget %d"
          % (shape, min(args.limit, len(ranked) or 1), args.budget))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("shapes")
    p.set_defaults(fn=cmd_shapes)
    p = sub.add_parser("targets")
    p.add_argument("shape")
    p.add_argument("--top", type=int, default=40)
    p.set_defaults(fn=cmd_targets)
    p = sub.add_parser("run")
    p.add_argument("shape")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--budget", type=int, default=20)
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("run-motif")
    p.add_argument("motif")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--budget", type=int, default=20)
    p.set_defaults(fn=cmd_run_motif)
    p = sub.add_parser("next")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--budget", type=int, default=20)
    p.set_defaults(fn=cmd_next)
    args = ap.parse_args()
    os.makedirs(STATE, exist_ok=True)
    args.fn(args)


if __name__ == "__main__":
    main()
