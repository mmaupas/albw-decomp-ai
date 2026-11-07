"""Coverage-weighted ranking of the near-miss backlog (3dsrecomp/Zakuro idea).

  python tools/coverage_rank.py rank [--coverage logs/coverage/executed.jsonl]
                                     [--top N] [--json]
  python tools/coverage_rank.py explain <addr>

Idea (logs/decomp-tools-review.md, part 5A "coverage feedback loop"): a
matching decomp should work on what the game actually executes, not only on
what is structurally closest. An emulator run (Azahar/Citra fork, or
Zakuro's interpreter mode) can log every executed function address; this
tool joins that coverage log with `worklist.py report` and re-ranks the
backlog by hotness x similarity.

Coverage input format (JSONL, one object per line, all fields optional):
  {"addr": "005AB1D0", "hits": 12345}
  {"addr": 0x005AB1D0, "count": 12345}
Addresses are matched to the containing function start via funcs.json, and a
hit on any address inside a function counts for that function. Missing or
absent coverage file => every function counts as cold (rank == report order),
which is the validated default below.

Ranking: score = frac * (1 + log10(1 + hits)). `frac` is the current
near-miss fraction from the report. Cold functions keep their relative
order because log10(1+0) == 0.

Producing a real coverage log (documented, not run here — no emulator can
execute in this Termux environment):
  - Azahar/Citra fork: add a counter increment in the ARM11 interpreter/
    JIT block dispatch keyed on the current PC, dump as JSONL on exit.
  - Zakuro (3dsrecomp's HLE emulator): interpreter mode already decodes
    every instruction; log PCs in its interpreter loop.
  - Luma3DS-style real-hardware hook: log PCs from a syscall wrapper.
"""
import argparse
import json
import math
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fn
from common import ROOT

DEFAULT_COVERAGE = os.path.join(ROOT, "logs", "coverage", "executed.jsonl")
REPORT_CACHE = os.path.join(ROOT, "logs", "coverage", "report.json")


def load_report():
    """Near-miss rows from worklist.py report --json (cached for reruns)."""
    if os.path.exists(REPORT_CACHE):
        with open(REPORT_CACHE, encoding="utf-8") as stream:
            return json.load(stream)
    out = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "worklist.py"),
                          "report", "--json"], capture_output=True, text=True, cwd=ROOT)
    rows = json.loads(out.stdout)
    os.makedirs(os.path.dirname(REPORT_CACHE), exist_ok=True)
    with open(REPORT_CACHE, "w", encoding="utf-8") as stream:
        json.dump(rows, stream)
    return rows


def load_coverage(path):
    """Aggregate hits per function start from a JSONL coverage log."""
    hits = {}
    if not path or not os.path.exists(path):
        return hits
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            addr = d.get("addr", d.get("pc"))
            if addr is None:
                continue
            if isinstance(addr, str):
                # tolerate "005CBE9C", "005CBE9C+0x10", "0x005CBE9C"
                addr = addr.split("+")[0].removeprefix("0x").removeprefix("0X")
                addr = int(addr, 16)
            else:
                addr = int(addr)
            count = int(d.get("hits", d.get("count", 1)))
            start = fn.func_range(addr)[0]
            hits[start] = hits.get(start, 0) + count
    return hits


def rank(rows, hits):
    out = []
    for row in rows:
        addr = int(row["addr"], 16)
        start = fn.func_range(addr)[0]
        h = hits.get(start, 0)
        score = row["frac"] * (1.0 + math.log10(1 + h))
        out.append({"addr": row["addr"], "frac": row["frac"], "hits": h,
                    "score": score, "kind": row["kind"], "hypothesis": row["hypothesis"]})
    out.sort(key=lambda r: -r["score"])
    return out


def cmd_rank(args):
    rows = load_report()
    hits = load_coverage(args.coverage)
    ranked = rank(rows, hits)
    if args.json:
        print(json.dumps(ranked[:args.top] if args.top else ranked, indent=1))
        return 0
    print("coverage file: %s (%d functions covered)" % (args.coverage, len(hits)))
    print("rank  addr      frac   hits      score   kind")
    for i, r in enumerate(ranked[:args.top]):
        print("%4d  %s  %.2f  %-9d %.4f  %s" % (i + 1, r["addr"], r["frac"], r["hits"], r["score"], r["kind"]))
    return 0


def cmd_explain(args):
    addr = int(args.addr, 16)
    start = fn.func_range(addr)[0]
    rows = load_report()
    row = next((r for r in rows if int(r["addr"], 16) == addr), None)
    hits = load_coverage(args.coverage)
    h = hits.get(start, 0)
    if row is None:
        print("%08X is not in the near-miss backlog" % addr)
        return 1
    print("addr %s (function start %08X)" % (row["addr"], start))
    print("  frac=%.4f kind=%s checks=%d" % (row["frac"], row["kind"], row["checks"]))
    print("  origin: %s" % row["origin"])
    print("  hypothesis: %s" % row["hypothesis"])
    print("  coverage hits: %d -> score %.4f" % (h, row["frac"] * (1 + math.log10(1 + h))))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("rank")
    p.add_argument("--coverage", default=DEFAULT_COVERAGE)
    p.add_argument("--top", type=int, default=25)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_rank)
    p = sub.add_parser("explain")
    p.add_argument("addr")
    p.add_argument("--coverage", default=DEFAULT_COVERAGE)
    p.set_defaults(func=cmd_explain)
    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
