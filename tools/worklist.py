"""Worklist driver (automation phase 5): the small-agent loop in one command.

  python tools/worklist.py next [--budget 60] [--region LO-HI] [--json]
  python tools/worklist.py register <addr> [--src PATH] [--json]
  python tools/worklist.py report [--json]
  python tools/worklist.py status [--json]

`next` pulls the smallest unindexed candidate (triage, refreshed), skips
negative recipes and already-attempted shapes, and prints the ONE command to
run. Outcomes of earlier suggestions are learned from refine's own state
(logs/refine/<addr>/state.json): a MATCH waiting for registration becomes a
`register` suggestion; DEFER/BUDGET functions are skipped and show up in
`report` for manual review. Eligibility: a synth class, or an ops-sequence
twin with a registered source (exact mnemonic-sequence match in the dna
index). Nothing registers without fn.py check printing RESULT: MATCH —
`register` re-verifies the source at its final registered path.

State: logs/autodecomp/state.json. Subprocesses run with hard timeouts
(OOM/hang rules live here, not in the agent's memory).
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fn
import dna
import contextlib
import synth
from permuter import check_one
from sweep import DEFAULT_FLAGS
from audit import trick_reasons
from common import file_lock, read_json, write_json

ROOT = fn.ROOT
STATE_DIR = os.path.join(ROOT, "logs", "autodecomp")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
CAND_FILE = os.path.join(ROOT, "logs", "triage", "unindexed_candidate.txt")
AUTO_DIR = os.path.join(ROOT, "src", "work8", "auto")
DEFAULT_CC = "4.1/b1049"
INCLUDE_LINE = re.compile(r'(^[ \t]*#include\s+")([^"]+)(")', re.MULTILINE)


def load_state():
    if os.path.exists(STATE_FILE):
        return read_json(STATE_FILE)
    return {"attempted": {}, "registered": []}


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    write_json(STATE_FILE, state)


def load_status():
    return read_json(os.path.join(ROOT, "functions.json"))


def run_checked(argv, timeout):
    """Subprocess with a hard timeout, killed as a process group on hang."""
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, cwd=ROOT, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            p.kill()
        else:
            os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return None
    return out if p.returncode == 0 else None


def candidates():
    """Fresh smallest-first candidate list (triage rerun drops registered)."""
    if run_checked([sys.executable, os.path.join("tools", "triage.py")],
                   timeout=180) is None or not os.path.exists(CAND_FILE):
        sys.exit("triage refresh failed (timeout or no candidates file)")
    out = []
    for line in open(CAND_FILE):
        parts = line.split()
        if len(parts) == 2:
            out.append((int(parts[0], 16), int(parts[1])))
    return out


def refine_state(addr):
    p = os.path.join(ROOT, "logs", "refine", "%08X" % addr, "state.json")
    return read_json(p) if os.path.exists(p) else None


def ops_twin_map():
    """ops-sequence -> registered source paths, for twin eligibility."""
    if not os.path.exists(dna.DNA_FILE):
        with contextlib.redirect_stdout(sys.stderr):
            dna.build_index()
    status = load_status()
    m = {}
    for r in dna.load_index():
        entry = status.get(r["addr"])
        if entry and entry.get("path") and entry["status"] in ("honest", "hack"):
            m.setdefault(r["ops"], []).append(entry["path"])
    return m


# ----------------------------------------------------------------------- next

def next_candidate(budget, region, scan_cap=60, as_json=False):
    state = load_state()
    status = load_status()
    lo, hi = (int(x, 16) for x in region.split("-")) if region else (None, None)
    twins = None
    skipped, scanned, chosen = [], 0, None
    for addr, size in candidates():
        key = "%08X" % addr
        if key in status or key in state["registered"]:
            continue
        if lo is not None and not lo <= addr < hi:
            continue
        rstate = refine_state(addr)
        if rstate and (rstate.get("best") or {}).get("match"):
            chosen = dict(addr=key, size=size, outcome="MATCH-unregistered",
                          origin=rstate["origin"], checks=rstate["used"])
            break
        if key in state["attempted"]:
            skipped.append((key, size, "attempted:" + state["attempted"][key].get("status", "?")))
            continue
        scanned += 1
        if scanned > scan_cap:
            break
        # learn the outcome of a previous `next` suggestion from refine's state
        rstate = refine_state(addr)
        if rstate:
            state["attempted"][key] = {
                "status": rstate.get("status", "?"), "checks": rstate["used"],
                "origin": rstate["origin"], "size": size}
            skipped.append((key, size, "refined:" + rstate.get("status", "?")))
            continue
        try:
            s, e, ins = synth.view(addr)
        except Exception as exc:
            state["attempted"][key] = {"status": "error", "reason": str(exc)[:60], "size": size}
            skipped.append((key, size, "view-error"))
            continue
        neg = synth.check_negative(ins)
        if neg:
            state["attempted"][key] = {"status": "negative", "recipe": neg, "size": size}
            skipped.append((key, size, "negative:" + neg))
            continue
        cls = synth.classify(ins)
        if cls:
            chosen = dict(addr=key, size=size, outcome="new", cls=cls)
            break
        # no synth class: still worth a shot if a registered twin has the
        # exact same mnemonic sequence (refine's auto start uses it)
        if twins is None:
            twins = ops_twin_map()
        ops = " ".join(dna.ops_seq(s, e))
        if twins.get(ops):
            chosen = dict(addr=key, size=size, outcome="new", cls="twin:" + twins[ops][0])
            break
        state["attempted"][key] = {"status": "no-start", "size": size}
        skipped.append((key, size, "no synth class, no ops twin"))
    save_state(state)
    if as_json:
        print(json.dumps({"chosen": chosen, "skipped": skipped[:12]}))
        return
    if chosen is None:
        print("QUEUE EMPTY within scan cap %d (%d skipped this pass)" % (scan_cap, len(skipped)))
        print("NEXT  python tools/worklist.py report  # manual review backlog")
        return
    if chosen["outcome"] == "MATCH-unregistered":
        print("CANDIDATE 0x%s (%dB) refined to MATCH but not registered yet" % (
            chosen["addr"], chosen["size"]))
        print("NEXT  python tools/worklist.py register 0x%s" % chosen["addr"])
    else:
        print("CANDIDATE 0x%s (%dB, %s, no negative recipe)" % (
            chosen["addr"], chosen["size"], chosen["cls"]))
        print("NEXT  python tools/refine.py 0x%s --budget %d" % (chosen["addr"], budget))
    if skipped:
        print("  (%d earlier candidates skipped: %s%s)" % (
            len(skipped), ", ".join("%s(%s)" % (k, r) for k, _s, r in skipped[:6]),
            " ..." if len(skipped) > 6 else ""))


# ------------------------------------------------------------------- register

def rebase_includes(text, dest_dir):
    """Absolute #includes (twin fixups) -> paths relative to the dest file."""
    out = []
    for line in text.splitlines():
        m = INCLUDE_LINE.match(line)
        if m and os.path.isabs(m.group(2)):
            included = os.path.realpath(m.group(2))
            if os.path.commonpath([os.path.realpath(ROOT), included]) == os.path.realpath(ROOT):
                line = m.group(1) + os.path.relpath(included, dest_dir) + m.group(3) + line[m.end():]
        out.append(line)
    return "\n".join(out) + "\n"


def register(addr, src=None, flags=None, as_json=False):
    """Publish a new, verified honest source; never replace an existing entry."""
    with file_lock(os.path.join(ROOT, "logs", "worklist.lock")):
        return _register(addr, src, flags, as_json)


def _register(addr, src, flags, as_json):
    key = "%08X" % addr
    if addr not in fn.STARTS:
        raise ValueError("registration requires an exact function start: " + key)
    status = load_status()
    if key in status:
        raise ValueError("refusing to replace existing index entry: " + key)
    rstate = refine_state(addr)
    best = (rstate or {}).get("best") or {}
    if src is None:
        src = best.get("path")
    if not src or not os.path.isfile(src):
        raise ValueError("no checked source to register; pass --src or run refine.py")
    if flags is None:
        flags = best.get("flags", DEFAULT_FLAGS)
    cc = (rstate or {}).get("cc", DEFAULT_CC)
    ext = os.path.splitext(src)[1]
    if ext not in (".c", ".cpp", ".cc"):
        raise ValueError("unsupported source extension: " + ext)
    dest = os.path.join(AUTO_DIR, "func_%s%s" % (key, ext))
    with open(src, encoding="utf-8") as stream:
        text = rebase_includes(stream.read(), AUTO_DIR)
    tricks = trick_reasons(text)
    if tricks:
        raise ValueError("honest registration refused: " + ", ".join(tricks))
    bad = [m.group(2) for m in INCLUDE_LINE.finditer(text) if os.path.isabs(m.group(2))]
    if bad:
        raise ValueError("PATH AUDIT FAILED: absolute include: " + bad[0])
    os.makedirs(AUTO_DIR, exist_ok=True)
    if os.path.realpath(AUTO_DIR) != os.path.abspath(AUTO_DIR):
        raise ValueError("registration directory must not traverse a symlink")
    # Exclusive creation also protects an unindexed source left by an earlier crash.
    with open(dest, "x", encoding="utf-8") as stream:
        stream.write(text)
    published = False
    try:
        result = check_one(AUTO_DIR, dest, addr, flags, None, cc=cc)
        if not result["match"] or result["err"]:
            raise ValueError("registration refused: " + (result["err"] or "NO MATCH"))
        rel = os.path.relpath(dest, ROOT)
        status[key] = {"cc": cc, "flags": flags, "hack_reasons": [],
                       "path": rel, "status": "honest"}
        write_json(os.path.join(ROOT, "functions.json"), status, canonical=True)
        published = True
        state = load_state()
        if key not in state["registered"]:
            state["registered"].append(key)
        state["attempted"].pop(key, None)
        save_state(state)
    finally:
        obj = os.path.splitext(dest)[0] + ".o"
        if os.path.exists(obj):
            os.unlink(obj)
        if not published:
            # Replacement may have committed just before an interruption. Never
            # remove a source unless the on-disk index proves it is unreferenced.
            try:
                published = load_status().get(key, {}).get("path") == os.path.relpath(dest, ROOT)
            except (OSError, ValueError):
                published = True  # preserve evidence if publication cannot be determined
            if not published:
                os.unlink(dest)
    output = {"addr": key, "path": rel, "status": "honest", "cc": cc, "flags": flags}
    if as_json:
        print(json.dumps(output))
    else:
        print("RESULT: MATCH %d/%d words -> %s" % (result["words"], result["total"], rel))
        print("NEXT  python3 tools/audit.py  # review changes before staging or committing")
    return output


# --------------------------------------------------------------------- report

def report(as_json=False):
    """Near-miss table: every attempted-but-unmatched function, closest first."""
    state = load_state()
    status = load_status()
    rows = []
    for key, info in state["attempted"].items():
        if key in status:
            continue
        rstate = refine_state(int(key, 16))
        if not rstate:
            rows.append(dict(addr=key, kind=info.get("status", "?"), frac=0.0,
                             hypothesis="no refine state (negative / no-start / error)"))
            continue
        b = rstate.get("best")
        if not b:
            rows.append(dict(addr=key, kind=rstate.get("status", "DEFER"), frac=0.0,
                             hypothesis=rstate.get("reason", "no starting source")))
            continue
        if b.get("match"):
            rows.append(dict(addr=key, kind="MATCH-unregistered", frac=1.0,
                             hypothesis="run: python tools/worklist.py register 0x%s" % key))
            continue
        frac = b["words"] / b["total"] if b["total"] else 0.0
        if b["n_op"] == 0 and b["n_reg"] > 0:
            hyp = "allocation-only delta: statement order / locals / flag variants"
        elif b["perm"]:
            hyp = "pure reordering: BODY permutation sweep (sweep.py)"
        elif rstate["origin"].startswith("twin"):
            hyp = "twin is the wrong construct: try the synth skeleton or sweep"
        else:
            hyp = "construct differs (%d OP): check recipes / sweep this shape" % b["n_op"]
        if rstate.get("status") == "BUDGET":
            hyp += "; budget exhausted — retry with a higher --budget first"
        rows.append(dict(addr=key, kind="OP=%d REG=%d%s" % (b["n_op"], b["n_reg"],
                                                           " PERM" if b["perm"] else ""),
                         frac=frac, checks=rstate["used"], origin=rstate["origin"],
                         hypothesis=hyp))
    rows.sort(key=lambda r: -r["frac"])
    if as_json:
        print(json.dumps(rows))
        return
    print("near-miss backlog (%d, closest first):" % len(rows))
    for r in rows:
        print("  %s  %-16s %3.0f%%  %s" % (
            r["addr"], r["kind"], r["frac"] * 100, r["hypothesis"][:96]))
    print("NEXT  pick one: refine.py with a higher budget, or sweep.py by hand")


def status_summary(as_json=False):
    state = load_state()
    n_cand = sum(1 for _ in open(CAND_FILE)) if os.path.exists(CAND_FILE) else -1
    waiting = sum(1 for k in state["attempted"]
                  if ((refine_state(int(k, 16)) or {}).get("best") or {}).get("match"))
    s = {"candidates": n_cand, "attempted": len(state["attempted"]),
         "registered": len(state["registered"]), "match_waiting": waiting}
    if as_json:
        print(json.dumps(s))
    else:
        print("worklist: %s candidates, %d attempted, %d registered, %d waiting to register" % (
            s["candidates"], s["attempted"], s["registered"], s["match_waiting"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["next", "register", "report", "status"])
    ap.add_argument("addr", nargs="?")
    ap.add_argument("--budget", type=int, default=60)
    ap.add_argument("--region")
    ap.add_argument("--src")
    ap.add_argument("--flags", help="override flags (default: refine state / fn.py defaults)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.cmd == "next":
        with file_lock(os.path.join(ROOT, "logs", "worklist.lock")):
            next_candidate(a.budget, a.region, as_json=a.json)
    elif a.cmd == "register":
        if not a.addr:
            sys.exit("register needs an address")
        register(int(a.addr, 16), src=a.src, flags=a.flags, as_json=a.json)
    elif a.cmd == "report":
        report(as_json=a.json)
    else:
        status_summary(as_json=a.json)


if __name__ == "__main__":
    main()
