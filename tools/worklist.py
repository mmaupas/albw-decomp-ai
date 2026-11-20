"""Worklist driver (automation phase 5): the small-agent loop in one command.

  python tools/worklist.py next [--budget 60] [--region LO-HI] [--json]
  python tools/worklist.py register <addr> [--src PATH] [--json]
  python tools/worklist.py verify <addr> [--src PATH] [--budget N] [--count N] [--wall-class CLASS] [--json]
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
`register` re-verifies the source at its final registered path, and it
refuses src_lifted/ sources outright (lifted code is semantic, never
byte-exact).

`report` --json rows carry the legacy fields (addr/kind/frac/checks/origin/
hypothesis) plus the aligned ecosystem fields score/max_score/diff/flags_tried/
permuter added side by side (field map: docs/AUTOMATION_PLAN.md phase 10);
`status` --json adds the permuter tried-cache hit-rate summary.

`verify` (roadmap C2+C3) runs the behavioral oracle for one candidate
(near-miss or lifted stub): it emits a RECOMP_OVERRIDE skeleton under
logs/verify/<ADDR>/, runs behavioral_oracle.py (3dsrecomp verify against
the Zakuro replay corpus in logs/coverage/, ZAKURO_RECORD/ZAKURO_REPLAY)
and records the verdict. A pass on a committable candidate path records
status "semantic_match" with a required wall_class in functions.json —
byte diffs remain, behavior equal on the corpus; it never counts toward
honest bytes. Serialized through the repo lock, budgeted (--budget oracle
runs per invocation), resumable (logs/verify/<ADDR>/state.json). Without
the corpus/harness/ROM it prints exactly how to produce them and exits
non-zero. First eligible candidates: the parked walls 005AB1D0,
0059F7B8, 005A8AA0, 005CBE9C (docs/AUTOMATION_PLAN.md phase 7).

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
from permuter import cache_stats, check_one, load_tried, state_for_addr
from sweep import DEFAULT_FLAGS
from audit import WALL_CLASSES, trick_reasons
from common import file_lock, read_json, write_json

ROOT = fn.ROOT
STATE_DIR = os.path.join(ROOT, "logs", "autodecomp")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
CAND_FILE = os.path.join(ROOT, "logs", "triage", "unindexed_candidate.txt")
AUTO_DIR = os.path.join(ROOT, "src", "work8", "auto")
VERIFY_DIR = os.path.join(ROOT, "logs", "verify")
CORPUS_DIR = os.path.join(ROOT, "logs", "coverage")
DEFAULT_CC = "4.1/b1049"
INCLUDE_LINE = re.compile(r'(^[ \t]*#include\s+")([^"]+)(")', re.MULTILINE)
# parked near-miss walls, first eligible `verify` candidates (roadmap C3)
PARKED_WALLS = ("005AB1D0", "0059F7B8", "005A8AA0", "005CBE9C")


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


def refine_flags_tried(addr):
    """Distinct flag strings checked for this target (refine history.jsonl)."""
    path = os.path.join(ROOT, "logs", "refine", "%08X" % addr, "history.jsonl")
    out = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                flags = rec.get("flags")
                if flags and flags not in out:
                    out.append(flags)
    return out


def permuter_state(key):
    """Permuter tried-cache outcome for one address (None when never permuted)."""
    return state_for_addr(key, ROOT)


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
    # lifted scaffolds (tools/lift.py) are semantic, never byte-exact: they
    # can never be registered as matched/honest/hack
    lifted_root = os.path.realpath(os.path.join(ROOT, "src_lifted"))
    for candidate in (src,):
        if os.path.realpath(candidate).startswith(lifted_root + os.sep):
            raise ValueError("lifted source under src_lifted/ is never registrable as matched: " + src)
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
                             diff=dict(op=b.get("n_op", 0), reg=b.get("n_reg", 0),
                                       perm=bool(b.get("perm"))),
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
                         diff=dict(op=b["n_op"], reg=b["n_reg"], perm=bool(b["perm"])),
                         hypothesis=hyp))
    # aligned (ecosystem) fields, added alongside the existing ones: score is the
    # same word-match fraction as frac, diff exposes the OP/REG class numerically,
    # flags_tried lists the flag sets actually checked, permuter surfaces the
    # permuter's tried-cache outcome for the address (None when never permuted)
    for row in rows:
        row["score"] = row["frac"]
        row["max_score"] = 1.0
        row["flags_tried"] = refine_flags_tried(int(row["addr"], 16))
        row["permuter"] = permuter_state(row["addr"])
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
         "registered": len(state["registered"]), "match_waiting": waiting,
         "permuter": cache_stats(load_tried(ROOT))}
    if as_json:
        print(json.dumps(s))
    else:
        print("worklist: %s candidates, %d attempted, %d registered, %d waiting to register" % (
            s["candidates"], s["attempted"], s["registered"], s["match_waiting"]))


# --------------------------------------------------------------------- verify

CORPUS_HINT = """behavioral oracle cannot run here: missing {missing}.
Produce the Zakuro replay corpus and harness on the phone (Termux), then re-run:
  # 1. deterministic replay corpus (ZAKURO_RECORD) into logs/coverage/:
  ZAKURO_RECORD=logs/coverage/replay.bin zakuro <decrypted USA .3ds> --frames 600
  #    (verify it replays: ZAKURO_REPLAY=logs/coverage/replay.bin zakuro <rom> --frames 600)
  # 2. 3dsrecomp verify harness (scratch, not committed):
  git clone --depth 1 https://github.com/fearkov/3dsrecomp ~/zakuro-work/3dsrecomp-src
  cd ~/zakuro-work/3dsrecomp-src && cargo build --release --features verify
  #    plus the minilib (~/zakuro-work/minilib/{{recomp.h,entries.c,ov.c}}) - see
  #    tools/behavioral_oracle.py docstring; ov.c is the RECOMP_OVERRIDE skeleton
  #    this command emits at logs/verify/{addr}/override.c
  # 3. then: uv run python tools/worklist.py verify {addr} --count 500
See docs/RECOMP_IDEAS.md section 3 and docs/AUTOMATION_PLAN.md phase 7."""


def find_corpus():
    """The Zakuro replay corpus: $ZAKURO_REPLAY, else logs/coverage/replay*."""
    env = os.environ.get("ZAKURO_REPLAY")
    if env and os.path.exists(env):
        return env
    if os.path.isdir(CORPUS_DIR):
        for name in sorted(os.listdir(CORPUS_DIR)):
            if name.startswith("replay"):
                return os.path.join(CORPUS_DIR, name)
    return None


def oracle_prereqs():
    """Missing pieces of the oracle chain, as human-readable names."""
    import behavioral_oracle as bo
    missing = []
    if find_corpus() is None:
        missing.append("Zakuro replay corpus (logs/coverage/replay* or $ZAKURO_REPLAY)")
    if not os.path.exists(bo.RECOMP):
        missing.append("3dsrecomp verify binary (%s)" % bo.RECOMP)
    if bo.find_rom(None) is None:
        missing.append("decrypted USA ROM (--rom / $ALBW_ROM / ~/Download)")
    return missing


def verify_state_file(key):
    return os.path.join(VERIFY_DIR, key, "state.json")


def load_verify_state(key):
    p = verify_state_file(key)
    return read_json(p) if os.path.exists(p) else {}


def save_verify_state(key, state):
    write_json(verify_state_file(key), state)


def candidate_source(addr, src=None):
    """Resolve the candidate source for verify: --src, a lifted entry, or the
    refine near-miss best source. Returns (rel_path_or_None, origin)."""
    key = "%08X" % addr
    if src is not None:
        full = src if os.path.isabs(src) else os.path.join(ROOT, src)
        if not os.path.isfile(full):
            raise ValueError("no such candidate source: " + src)
        return os.path.relpath(os.path.abspath(full), ROOT), "--src"
    status = load_status()
    ent = status.get(key) or {}
    if ent.get("status") == "lifted" and ent.get("path"):
        return ent["path"], "lifted"
    if ent.get("status") == "semantic_match":
        return ent.get("path"), "already-verified"
    if ent.get("status") in ("honest", "hack"):
        return ent.get("path"), "matched (byte-exact already; nothing to verify)"
    rstate = refine_state(addr)
    best = (rstate or {}).get("best") or {}
    if best.get("path") and os.path.isfile(best["path"]):
        return os.path.relpath(best["path"], ROOT), "refine-near-miss"
    return None, "none"


def emit_override_text(addr, src_path):
    """RECOMP_OVERRIDE skeleton for the 3dsrecomp harness (logs/verify/<ADDR>/override.c)."""
    return ("/* RECOMP_OVERRIDE skeleton emitted by tools/worklist.py verify.\n"
            " * Candidate source: %s\n"
            " * Fill the body (lifted stubs under src_lifted/ translate statement-by-\n"
            " * statement), then run: python tools/worklist.py verify 0x%08X\n"
            " */\n"
            '#include "recomp.h"\n'
            "RECOMP_OVERRIDE(0x%08X) {\n"
            "    return 0;\n"
            "}\n" % (src_path or "(none)", addr, addr))


def parse_verdict(output):
    """Parse 3dsrecomp verify output -> (passed, mismatches) or (None, None)."""
    m = re.search(r"(\d+) returned, (\d+) mismatched", output)
    if m:
        return int(m.group(2)) == 0, int(m.group(2))
    if re.search(r"\b0 mismatched\b", output):
        return True, 0
    if "mismatched" in output:
        return False, None
    return None, None


def is_tracked(path):
    r = subprocess.run(["git", "-C", ROOT, "ls-files", "--error-unmatch", path],
                       capture_output=True, text=True)
    return r.returncode == 0


def record_semantic_match(key, path, wall_class, cc=None, flags=None, locked=False):
    """Record a semantic_match verdict in functions.json (never touches matched
    entries, never counts toward honest bytes). `locked` is for callers that
    already hold the worklist lock (the lock is not reentrant)."""
    def publish():
        status = load_status()
        ent = status.get(key)
        if ent and ent.get("status") in ("honest", "hack"):
            raise ValueError("refusing to overwrite matched entry " + key)
        rec = {"path": path, "status": "semantic_match", "wall_class": wall_class}
        if cc:
            rec["cc"] = cc
        if flags:
            rec["flags"] = flags
        status[key] = rec
        write_json(os.path.join(ROOT, "functions.json"), status, canonical=True)
    if locked:
        publish()
    else:
        with file_lock(os.path.join(ROOT, "logs", "worklist.lock")):
            publish()


def run_oracle(addr, count, timeout=600):
    """Run behavioral_oracle verify for one address; returns (rc, output).
    Output is captured whatever the exit code (a mismatch verdict is data)."""
    key = "%08X" % addr
    corpus = find_corpus()
    env = dict(os.environ)
    if corpus:
        env["ZAKURO_REPLAY"] = corpus
    argv = [sys.executable, os.path.join(ROOT, "tools", "behavioral_oracle.py"),
            "verify", key, "--count", str(count)]
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, cwd=ROOT, env=env, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            p.kill()
        else:
            os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return None, "timeout after %ds" % timeout
    return p.returncode, out


def verify(addr, src=None, budget=1, count=500, wall_class="unknown", as_json=False, runner=None):
    """One oracle verdict for one candidate. Budgeted (--budget oracle runs per
    invocation), resumable (logs/verify/<ADDR>/state.json), serialized (lock)."""
    key = "%08X" % addr
    if addr not in fn.STARTS:
        raise ValueError("verify requires an exact function start: " + key)
    if wall_class not in WALL_CLASSES:
        raise ValueError("wall_class must be one of %r" % (WALL_CLASSES,))
    with file_lock(os.path.join(ROOT, "logs", "worklist.lock")):
        state = load_state()
        vstate = load_verify_state(key)
        runs = vstate.get("runs", 0)
        if runs >= budget:
            out = {"addr": key, "status": "budget-exhausted", "runs": runs,
                   "last": vstate.get("last")}
            if as_json:
                print(json.dumps(out))
            else:
                print("verify %s: budget exhausted (%d runs); raise --budget" % (key, runs))
            return 0
        path, origin = candidate_source(addr, src)
        os.makedirs(os.path.join(VERIFY_DIR, key), exist_ok=True)
        override = os.path.join(VERIFY_DIR, key, "override.c")
        with open(override, "w", encoding="utf-8") as fh:
            fh.write(emit_override_text(addr, path))
        missing = oracle_prereqs()
        if missing:
            vstate.update({"runs": runs + 1, "last": {"status": "blocked", "missing": missing,
                                                       "override": os.path.relpath(override, ROOT),
                                                       "candidate": path, "origin": origin}})
            save_verify_state(key, vstate)
            msg = CORPUS_HINT.format(missing=", ".join(missing), addr=key)
            if as_json:
                print(json.dumps({"addr": key, "status": "blocked", "missing": missing,
                                  "candidate": path, "origin": origin,
                                  "override": os.path.relpath(override, ROOT)}))
            else:
                print(msg)
            return 2
        rc, output = (runner or run_oracle)(addr, count)
        passed, mismatches = parse_verdict(output or "")
        verdict = {"status": "pass" if passed else ("fail" if passed is False else "unknown"),
                   "mismatches": mismatches, "rc": rc, "output_tail": (output or "")[-400:],
                   "candidate": path, "origin": origin, "wall_class": wall_class,
                   "override": os.path.relpath(override, ROOT)}
        vstate.update({"runs": runs + 1, "last": verdict})
        save_verify_state(key, vstate)
        state.setdefault("verified", {})[key] = verdict["status"]
        save_state(state)
        published = None
        if passed and path and is_tracked(path):
            ent = load_status().get(key) or {}
            record_semantic_match(key, path, wall_class, ent.get("cc"), ent.get("flags"), locked=True)
            published = "semantic_match"
        out = {"addr": key, "verdict": verdict["status"], "mismatches": mismatches,
               "candidate": path, "origin": origin, "published": published,
               "override": os.path.relpath(override, ROOT)}
        if as_json:
            print(json.dumps(out))
        else:
            print("verify %s: %s (mismatches=%s) candidate=%s (%s)" % (
                key, verdict["status"], mismatches, path, origin))
            if published:
                print("published: functions.json[%s] = semantic_match (wall_class=%s); not counted toward honest bytes" % (key, wall_class))
            elif passed and path and not is_tracked(path):
                print("verdict recorded in logs/verify/%s/state.json only: %s is not git-tracked;" % (key, path))
                print("commit the candidate source and re-run verify to publish semantic_match")
            print("NEXT  python tools/audit.py  # semantic_match stays disjoint from matched")
        return 0 if verdict["status"] != "fail" else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["next", "register", "verify", "report", "status"])
    ap.add_argument("addr", nargs="?")
    ap.add_argument("--budget", type=int, default=None,
                    help="next: refine checks (default 60); verify: oracle runs (default 1)")
    ap.add_argument("--region")
    ap.add_argument("--src")
    ap.add_argument("--flags", help="override flags (default: refine state / fn.py defaults)")
    ap.add_argument("--count", type=int, default=500, help="oracle sample count (verify)")
    ap.add_argument("--wall-class", default="unknown", choices=WALL_CLASSES,
                    help="wall_class recorded with a semantic_match verdict")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    budget = a.budget if a.budget is not None else (1 if a.cmd == "verify" else 60)
    if a.cmd == "next":
        with file_lock(os.path.join(ROOT, "logs", "worklist.lock")):
            next_candidate(budget, a.region, as_json=a.json)
    elif a.cmd == "register":
        if not a.addr:
            sys.exit("register needs an address")
        register(int(a.addr, 16), src=a.src, flags=a.flags, as_json=a.json)
    elif a.cmd == "verify":
        if not a.addr:
            sys.exit("verify needs an address")
        sys.exit(verify(int(a.addr, 16), src=a.src, budget=budget, count=a.count,
                        wall_class=a.wall_class, as_json=a.json))
    elif a.cmd == "report":
        report(as_json=a.json)
    else:
        status_summary(as_json=a.json)


if __name__ == "__main__":
    main()
