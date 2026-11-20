"""Automated variant sweep for a near-miss function (ZeldaRET-permuter style, local armcc+wine).

  python tools/permuter.py <addr> <spec.py> [--jobs 1] [--stop-on-match] [--fresh] [--json]
  python tools/permuter.py status [--json]

spec.py defines:
  TEMPLATE - source string with {slot} placeholders
  GRID     - dict: slot -> list of candidate substitution strings (cartesian product)
  FLAGS    - optional list of flag-sets to sweep (default: fn.py default flags only)
  SYM      - optional mangled-name substring passed to fn.py check --sym

Each variant is compiled and checked by `fn.py check` in its own process group
(wine can hang: every child is killpg'd on timeout). Results ranked by word
score; the full sweep log lands beside the variants, matches print the source.

Tried-memory (logs/permuter/tried.json, gitignored): every checked candidate is
recorded under a SHA-256 key over its normalized source (comments/whitespace
stripped, see normalize_source) + target address + cc + flags. A later run
skips candidates already rejected under the same key instead of re-burning
compile budget, logs the skip count, and `status` reports the hit rate.
--fresh bypasses the cache for a clean run. The cache only prevents wasted
work: it never invents candidates, and a skipped candidate is still ranked by
its recorded score.
"""
import hashlib
import importlib.util, itertools, json, os, re, signal, subprocess, sys, tempfile, time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from common import read_json, write_json
from fn import DEFAULT_CC, DEFAULT_FLAGS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULT_RE = re.compile(r"^RESULT: (MATCH|NO MATCH)[ \t]+(\d+)/(\d+) words \(([\d.]+)%\)[ \t]+similarity ([\d.]+)%[ \t]*$", re.MULTILINE)
TRIED_REL = os.path.join("logs", "permuter", "tried.json")
COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
SPACE_RE = re.compile(r"\s+")
LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
PUNCT_SPACE_RE = re.compile(r"\s*([^\w\s])\s*")


# ------------------------------------------------------------- tried-memory

def _squash_code(code):
    """Whitespace churn in code (outside literals): runs collapse to one space
    and spaces around punctuation are dropped, so reformatting is ignored."""
    return SPACE_RE.sub(" ", PUNCT_SPACE_RE.sub(r"\1", code))


def normalize_source(text):
    """Canonical form of a candidate source for cache keying: comments removed
    and whitespace churn squashed (string/char literals kept verbatim), so
    cosmetic edits do not defeat the cache."""
    text = COMMENT_RE.sub(" ", text)
    parts, pos = [], 0
    for m in LITERAL_RE.finditer(text):
        parts.append(_squash_code(text[pos:m.start()]))
        parts.append(m.group(0))
        pos = m.end()
    parts.append(_squash_code(text[pos:]))
    return "".join(parts).strip()


def candidate_key(text, addr, cc, flags):
    """Stable tried-cache key: SHA-256 over the normalized candidate source
    plus the target address, compiler and flags it was checked with."""
    payload = json.dumps([normalize_source(text), "%08X" % addr, cc or "", flags or ""],
                         ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def tried_file(root=None):
    return os.path.join(root or ROOT, TRIED_REL)


def load_tried(root=None):
    """Load the tried-candidates cache; a missing or corrupt file starts empty."""
    path = tried_file(root)
    if os.path.exists(path):
        try:
            data = read_json(path)
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict) and isinstance(data.get("entries"), dict):
            data.setdefault("version", 1)
            data.setdefault("stats", {"lookups": 0, "hits": 0})
            return data
    return {"version": 1, "entries": {}, "stats": {"lookups": 0, "hits": 0}}


def save_tried(tried, root=None):
    write_json(tried_file(root), tried)


def new_run_id():
    return "%s-%s" % (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), uuid.uuid4().hex[:8])


def record_outcome(tried, key, addr, cc, flags, result, run_id):
    """Persist one checked candidate: outcome + score summary, timestamp, run id."""
    words, total = int(result.get("words") or 0), int(result.get("total") or 0)
    entry = {"outcome": "match" if result.get("match") else "rejected",
             "addr": "%08X" % addr, "cc": cc or "", "flags": flags or "",
             "words": words, "total": total, "score": round(words / max(total, 1), 6),
             "sim": float(result.get("sim") or 0.0), "err": (result.get("err") or "")[:120],
             "ts": datetime.now(timezone.utc).isoformat(), "run": run_id}
    tried["entries"][key] = entry
    return entry


def lookup_tried(tried, key, fresh=False):
    """Cache lookup: the known-rejected entry to skip, or None. Every lookup is
    counted so `status` can report a hit rate. --fresh bypasses the cache."""
    stats = tried.setdefault("stats", {"lookups": 0, "hits": 0})
    stats["lookups"] = stats.get("lookups", 0) + 1
    if fresh:
        return None
    entry = tried["entries"].get(key)
    if entry and entry.get("outcome") == "rejected":
        stats["hits"] = stats.get("hits", 0) + 1
        entry["skips"] = entry.get("skips", 0) + 1
        return entry
    return None


def cache_stats(tried):
    """Hit-rate summary of the tried-cache (surfaced by `status` and reports)."""
    entries = tried.get("entries", {})
    stats = tried.get("stats", {})
    lookups, hits = stats.get("lookups", 0), stats.get("hits", 0)
    return {"entries": len(entries),
            "rejected": sum(1 for e in entries.values() if e.get("outcome") == "rejected"),
            "match": sum(1 for e in entries.values() if e.get("outcome") == "match"),
            "lookups": lookups, "hits": hits,
            "hit_rate": round(hits / lookups, 6) if lookups else 0.0,
            "skips": sum(e.get("skips", 0) for e in entries.values()),
            "cache": TRIED_REL}


def state_for_addr(key, root=None):
    """Permuter tried-cache summary for one function address (report surfacing)."""
    entries = [e for e in load_tried(root)["entries"].values() if e.get("addr") == key]
    if not entries:
        return None
    best = max(entries, key=lambda e: (e.get("outcome") == "match", e.get("score") or 0.0))
    return {"entries": len(entries),
            "rejected": sum(1 for e in entries if e.get("outcome") == "rejected"),
            "skips": sum(e.get("skips", 0) for e in entries),
            "best": {"outcome": best.get("outcome"), "score": best.get("score"),
                     "sim": best.get("sim"), "flags": best.get("flags"), "run": best.get("run")}}


def status(as_json=False, root=None):
    """Tried-cache report: entries, outcomes, lookups/hits and the hit rate."""
    out = cache_stats(load_tried(root))
    if as_json:
        print(json.dumps(out))
    else:
        print("permuter tried-cache (%s): %d entries (%d rejected, %d match), "
              "%d lookups, %d hits (hit rate %.1f%%), %d skips" % (
                  TRIED_REL, out["entries"], out["rejected"], out["match"],
                  out["lookups"], out["hits"], out["hit_rate"] * 100, out["skips"]))
        print("NEXT  python tools/permuter.py <addr> <spec.py>  # known-rejected candidates are skipped")
    return out


def check_one(workdir, src, addr, flags, sym, timeout=300, cc="4.1/b1049"):
    args = [sys.executable, os.path.join(ROOT, "tools", "fn.py"), "check", src, "0x%08X" % addr,
            "--cc", cc, "--flags", flags]
    if sym:
        args += ["--sym", sym]
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         cwd=ROOT, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            p.kill()
        else:
            os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return dict(match=False, words=0, total=0, sim=0.0, err="TIMEOUT", out=out)
    if p.returncode:
        return dict(match=False, words=0, total=0, sim=0.0,
                    err="CHECK FAILED (exit %d): %s" % (p.returncode, out.strip()[-200:]), out=out)
    matches = list(RESULT_RE.finditer(out))
    m = matches[-1] if matches else None
    if "COMPILE ERROR" in out:
        first = out.splitlines()
        err = next((l for l in first if "error" in l.lower()), "compile error")[:120]
        return dict(match=False, words=0, total=0, sim=0.0, err=err, out=out)
    if not m:
        return dict(match=False, words=0, total=0, sim=0.0, err="NO OUTPUT", out=out)
    if m.group(1) == "MATCH" and (int(m.group(2)) != int(m.group(3)) or int(m.group(3)) == 0):
        return dict(match=False, words=0, total=0, sim=0.0, err="INVALID CHECK RESULT", out=out)
    return dict(match=m.group(1) == "MATCH", words=int(m.group(2)), total=int(m.group(3)),
                sim=float(m.group(5)), err="", out=out)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        status(as_json="--json" in sys.argv)
        return
    addr = int(sys.argv[1], 16)
    spec_path = sys.argv[2]
    jobs = int(sys.argv[sys.argv.index("--jobs") + 1]) if "--jobs" in sys.argv else 1
    if jobs != 1:
        sys.exit("Only --jobs 1 is supported: parallel compiler jobs can exhaust memory")
    stop_on_match = "--stop-on-match" in sys.argv
    fresh = "--fresh" in sys.argv
    as_json = "--json" in sys.argv

    def say(msg):
        # with --json, progress goes to stderr and stdout carries one JSON value
        print(msg, file=sys.stderr if as_json else sys.stdout)

    spec = importlib.util.spec_from_file_location("perm_spec", spec_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    slots = sorted(mod.GRID)
    combos = list(itertools.product(*(mod.GRID[k] for k in slots)))
    entry = read_json(os.path.join(ROOT, "functions.json")).get("%08X" % addr, {})
    cc = entry.get("cc", DEFAULT_CC)
    flagsets = getattr(mod, "FLAGS", None) or [entry.get("flags", DEFAULT_FLAGS)]
    total = len(combos) * len(flagsets)
    say(f"{len(combos)} variants x {len(flagsets)} flag-sets = {total} checks"
        + (" (--fresh: tried-cache bypassed)" if fresh else ""))

    workdir = tempfile.mkdtemp(prefix="perm_%08X_" % addr)
    results = []
    tried = load_tried()
    run_id = new_run_id()
    skipped = 0

    def run(idx_fl):
        idx, fi = idx_fl
        sub = dict(zip(slots, combos[idx]))
        # unique file per (variant, flag-set): fn.py derives the .o from the source name
        src = os.path.join(workdir, "v%04d_f%d.cpp" % (idx, fi))
        text = mod.TEMPLATE
        for k, v in sub.items():
            text = text.replace("{%s}" % k, v)
        with open(src, "w") as fh:
            fh.write(text)
        fl = flagsets[fi]
        flags = fl or entry.get("flags", DEFAULT_FLAGS)
        key = candidate_key(text, addr, cc, flags)
        cached = lookup_tried(tried, key, fresh=fresh)
        if cached is not None:
            # known-rejected under the same key: reuse the recorded score, no compile
            r = dict(match=False, words=cached.get("words", 0), total=cached.get("total", 0),
                     sim=cached.get("sim", 0.0), err="", out="", skipped=True)
        else:
            r = check_one(workdir, src, addr, flags, getattr(mod, "SYM", None), cc=cc)
            r["skipped"] = False
            record_outcome(tried, key, addr, cc, flags, r, run_id)
            save_tried(tried)
        r.update(idx=idx, flags=flags, src=src, **sub)
        return r

    t0 = time.time()
    all_jobs = [(i, fi) for i in range(len(combos)) for fi in range(len(flagsets))]
    pending = []
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        pending = [ex.submit(run, j) for j in all_jobs]

        for i, fut in enumerate(as_completed(pending)):
            r = fut.result()
            results.append(r)
            if r.get("skipped"):
                skipped += 1
            tag = "MATCH" if r["match"] else (f"cached {r['words']}/{r['total']}" if r.get("skipped")
                                              else f"{r['words']}/{r['total']}")
            say(f"[{i+1}/{total}] v{r['idx']:04d} {' '.join(f'{k}={r[k][:24]}' for k in slots if r.get(k))} "
                f"[{' '.join(r['flags'].split()[-3:-1])}] {tag} sim={r['sim']:.1f}" + (f" ERR: {r['err']}" if r["err"] else ""))
            if r["match"] and stop_on_match:
                for p in pending:
                    p.cancel()
                break

    save_tried(tried)
    results.sort(key=lambda r: (r["match"], r["words"] / max(r["total"], 1), r["sim"]), reverse=True)
    log = os.path.join(workdir, "results.txt")
    with open(log, "w") as fh:
        for r in results:
            fh.write("%s v%04d %s/%s sim=%.1f flags='%s'%s\n" % (
                "MATCH" if r["match"] else "     ", r["idx"], r["words"], r["total"], r["sim"], r["flags"],
                " cached" if r.get("skipped") else ""))
    say(f"\nbest of {len(results)} in {time.time()-t0:.0f}s | log: {log}")
    if skipped:
        say(f"skipped {skipped} known-rejected candidate(s) via tried-cache ({TRIED_REL}; --fresh bypasses)")
    for r in results[:5]:
        say(f"  v{r['idx']:04d} {'MATCH' if r['match'] else ''} {r['words']}/{r['total']} sim={r['sim']:.1f} {r['flags']}"
            + (" (cached)" if r.get("skipped") else ""))
    if results and results[0]["match"]:
        say(f"\nWINNER: {results[0]['src']}")
        say(open(results[0]["src"]).read())
    if as_json:
        def result_json(r):
            out = {k: r.get(k) for k in ("idx", "match", "words", "total", "sim", "flags",
                                         "src", "err", "skipped")}
            out["score"] = round(r["words"] / max(r["total"], 1), 6)
            out["max_score"] = 1.0
            out.update({k: r.get(k) for k in slots})
            return out
        best = result_json(results[0]) if results else None
        print(json.dumps({
            "addr": "%08X" % addr, "run_id": run_id,
            "variants": len(combos), "flag_sets": len(flagsets),
            "checks": len(results) - skipped, "skipped": skipped,
            "flags_tried": sorted({r["flags"] for r in results}),
            "results": [result_json(r) for r in results],
            "best": best,
            "permuter": dict(cache_stats(tried), run_id=run_id, fresh=fresh),
        }))


if __name__ == "__main__":
    main()
