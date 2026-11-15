#!/usr/bin/env python
"""Verification protocol for shapes admitted to shared/include/albw_shapes.h.

  python tools/shape_verify.py scan                 rebuild candidate call sites (offline)
  python tools/shape_verify.py verify [--sites N] [--shape albw::X]   oracle re-check
  python tools/shape_verify.py report [--json]      verdict table
  python tools/shape_verify.py lessons [--write]    render/check the LESSONS.md block

Protocol (see AGENTS.md): a shape admitted to the header must be
  1. byte-exact at >= 3 DISTINCT registered call sites — `fn.py check` on the
     site's registered source must print RESULT: MATCH (a shape verified once
     can silently be wrong in its variants, so >= 3 sites, never 1), and
  2. honest at those sites — status honest and no textually detectable
     forbidden trick (audit.trick_reasons).
Sites are functions whose registered source exhibits the shape: a reference
to the shape name (bare or qualified, header include or local same-name
definition) or, for shapes sources rename freely (Delegate, placement new),
a structural pattern. Verdicts and the full site lists live in the committed
report shared/shape_verification.json; docs/LESSONS.md carries a generated
block between <!-- shape-verification --> markers that CI freshness-checks
(`lessons` without --write exits 1 when stale).

`verify` needs code.bin + armcc and runs serially (OOM rule). State is the
JSON report itself: re-running resumes with already-checked sites kept.
"""
import argparse
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit import trick_reasons  # noqa: E402
from common import atomic_write, read_json, write_json  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER = os.path.join(ROOT, "shared", "include", "albw_shapes.h")
REPORT = os.path.join(ROOT, "shared", "shape_verification.json")
LESSONS = os.path.join(ROOT, "docs", "LESSONS.md")
BLOCK_BEGIN = "<!-- shape-verification -->"
BLOCK_END = "<!-- /shape-verification -->"
MIN_SITES = 3
DEFAULT_SITES = 6
MAX_CANDIDATES = 60

# Structural site patterns for shapes that sources rename freely. A source is
# a candidate site when it matches the name aliases OR all patterns here.
STRUCTURAL = {
    "albw::Delegate": [r"virtual\s+bool\s+\w+\s*\(", r"->\s*\*\s*\w+"],
    "operator new": [r"\bnew\s*\([^)]*,"],  # placement form: new (args, ptr)
    "albw::randRange": [r">>\s*32"],  # multiply-high PRNG: (u64)x * n >> 32
}


# ------------------------------------------------------------ shape registry

# Helper typedefs/members that belong to a bigger shape, not shapes themselves.
HELPERS = {"SmOwner_", "SmFunc", "SmTimeline", "DelegateOwner", "DelegateFn", "s64"}


def parse_shapes():
    """Enumerate shapes from the header: namespace::Name per struct/typedef/
    inline function, plus the placement operator new. Brace-depth tracked so
    struct bodies do not pop the namespace stack."""
    text = open(HEADER, encoding="utf-8").read()
    text = re.sub(r"//[^\n]*|/\*.*?\*/", " ", text, flags=re.DOTALL)
    shapes = {}
    ns = []      # list of (name, depth_at_open)
    depth = 0
    pat = re.compile(r"(?P<ns>namespace\s+(?P<nsname>\w+)\s*\{)"
                     r"|(?P<struct>struct\s+(?P<structname>\w+))"
                     r"|typedef\s+[^;()]*\(\s*\*?\s*(?P<fnptr>\w+)\s*\)\s*\([^;]*;"
                     r"|typedef\s+[^;{]+?\s+(?P<tdname>\w+)\s*;"
                     r"|inline\s+(?P<inret>[\w:<>\*& ]+?)\s*(?P<inname>\w+)\s*\("
                     r"|(?P<opnew>operator\s+new)|(?P<open>\{)|(?P<close>\})")
    for m in pat.finditer(text):
        if m.group("nsname") is not None:
            ns.append((m.group("nsname"), depth))
            depth += 1
        elif m.group("open"):
            depth += 1
        elif m.group("close"):
            depth -= 1
            while ns and depth <= ns[-1][1]:
                ns.pop()
        elif m.group("opnew"):
            shapes.setdefault("operator new", {"kind": "operator", "name": "operator new"})
        else:
            while ns and depth <= ns[-1][1]:
                ns.pop()
            name = m.group("structname") or m.group("fnptr") or m.group("tdname") or m.group("inname")
            kind = ("struct" if m.group("structname") else "typedef" if (m.group("fnptr") or m.group("tdname"))
                    else "inline-func")
            if not name or name in HELPERS:
                continue
            if kind == "inline-func" and "operator" in (m.group("inret") or ""):
                shapes.setdefault("operator new", {"kind": "operator", "name": "operator new"})
                continue
            if kind == "inline-func" and "::" in (m.group("inret") or ""):
                continue  # inline member definition (Delegate::invoke), not a shape
            q = "::".join([n for n, _ in ns] + [name])
            shapes.setdefault(q, {"kind": kind, "name": name})
    return shapes


def site_regexes(qname, name):
    pats = [r"\b%s\b" % re.escape(name), r"\b%s\b" % re.escape(qname)]
    pats += STRUCTURAL.get(qname, [])
    return pats


# ------------------------------------------------------------------- scanning

def load_sources():
    functions = read_json(os.path.join(ROOT, "functions.json"))
    out = []  # (addr_key, entry, text, includes_shapes_header)
    for key, ent in functions.items():
        path = ent.get("path")
        if not path:
            continue
        full = os.path.join(ROOT, path)
        if not os.path.isfile(full):
            continue
        with open(full, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        out.append((key, ent, text, "albw_shapes.h" in text))
    return functions, out


def cmd_scan(args):
    shapes = parse_shapes()
    functions, sources = load_sources()
    header_text = open(HEADER, encoding="utf-8").read()
    header_addrs = set(re.findall(r"\b([0-9A-F]{8})\b", header_text))
    report = read_json(REPORT) if os.path.exists(REPORT) else {"shapes": {}}
    old = report.get("shapes", {})
    new_shapes = {}
    for qname, meta in sorted(shapes.items()):
        name = meta["name"]
        pats = site_regexes(qname, name)
        comps = [re.compile(p) for p in pats]
        struct_all = [re.compile(p) for p in STRUCTURAL.get(qname, [])]
        sites = []
        for key, ent, text, has_header in sources:
            if any(c.search(text) for c in comps) and all(c.search(text) for c in struct_all):
                sites.append({"addr": key, "path": ent["path"], "status": ent.get("status"),
                              "check": None, "tricks": [], "header": has_header})
        # keep previous oracle results for sites that still exist
        prev = {s["addr"]: s for s in old.get(qname, {}).get("sites", [])}
        for s in sites:
            if s["addr"] in prev and prev[s["addr"]]["path"] == s["path"]:
                s["check"] = prev[s["addr"]].get("check")
                s["tricks"] = prev[s["addr"]].get("tricks", [])
        # strongest evidence first: header-including sources, addresses the
        # header itself claims as verified, worklist-registered (post-hardening)
        # sources, honest status, addr
        sites.sort(key=lambda s: (0 if s["header"] else 1,
                                  0 if s["addr"] in header_addrs else 1,
                                  0 if "/auto/" in s["path"] else 1,
                                  0 if s["status"] == "honest" else 1, s["addr"]))
        new_shapes[qname] = dict(meta, sites=sites[:MAX_CANDIDATES])
    report = {
        "protocol": ("byte-exact (fn.py check RESULT: MATCH) at >= %d distinct registered "
                     "call sites, honest (no forbidden tricks); sites recorded per shape"
                     % MIN_SITES),
        "min_sites": MIN_SITES,
        "header": "shared/include/albw_shapes.h",
        "verifier": None,
        "updated": None,
        "shapes": new_shapes,
    }
    write_json(REPORT, report, canonical=True)
    for qname, ent in new_shapes.items():
        print("%-28s %4d candidate sites" % (qname, len(ent["sites"])))
    print("NEXT  python tools/shape_verify.py verify --sites %d   # needs code.bin+armcc" % DEFAULT_SITES)


# ------------------------------------------------------------------ verifying

def verdict_of(ent):
    checked = [s for s in ent["sites"] if s.get("check") is not None]
    passed = [s for s in checked if s["check"] == "MATCH" and s["status"] == "honest" and not s["tricks"]]
    if len(passed) >= MIN_SITES:
        return "PASS"
    if len(checked) >= len(ent["sites"]):
        return "FAIL"
    return "PENDING"


def cmd_verify(args):
    from permuter import check_one
    from relocations import VERIFIER_VERSION
    report = read_json(REPORT)
    if not report.get("shapes"):
        sys.exit("no scan yet; run: python tools/shape_verify.py scan")
    functions = read_json(os.path.join(ROOT, "functions.json"))
    todo = args.shape if args.shape else sorted(report["shapes"])
    for qname in todo:
        ent = report["shapes"][qname]
        if not args.all and verdict_of(ent) == "PASS":
            print("%-28s already PASS (%d sites), skipping" % (qname, ent.get("verified", 0)), flush=True)
            continue
        n_new = 0
        for s in ent["sites"]:
            if n_new >= args.sites:
                break
            if s.get("check") is not None:
                continue
            entry = functions.get(s["addr"]) or {}
            flags = entry.get("flags") or "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections"
            cc = entry.get("cc", "4.1/b1049")
            full = os.path.join(ROOT, s["path"])
            with open(full, encoding="utf-8", errors="replace") as fh:
                s["tricks"] = trick_reasons(fh.read())
            r = check_one(os.path.dirname(full), full, int(s["addr"], 16), flags, None, cc=cc)
            if r.get("match") and not r.get("err"):
                s["check"] = "MATCH"
            elif "relocation identity not proved" in (r.get("out") or ""):
                s["check"] = "NO MATCH (reloc)"  # bytes align; a C++ mangled-name reloc is unproved
            else:
                s["check"] = "NO MATCH"
            n_new += 1
            ent["verdict"] = verdict_of(ent)
            report["verifier"] = VERIFIER_VERSION
            report["updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
            write_json(REPORT, report, canonical=True)
            print("%-28s %s %s -> %s" % (qname, s["addr"], s["status"], s["check"]), flush=True)
        ent["verdict"] = verdict_of(ent)
        ent["verified"] = sum(1 for s in ent["sites"]
                              if s.get("check") == "MATCH" and s["status"] == "honest" and not s["tricks"])
        write_json(REPORT, report, canonical=True)
        print("%-28s verdict=%s verified=%d/%d sites" % (qname, ent["verdict"], ent["verified"], len(ent["sites"])), flush=True)
    print("NEXT  python tools/shape_verify.py report && python tools/shape_verify.py lessons --write")


# -------------------------------------------------------------------- report

def cmd_report(args):
    report = read_json(REPORT)
    rows = []
    for qname, ent in sorted(report.get("shapes", {}).items()):
        ent.setdefault("verdict", verdict_of(ent))
        passed = [s["addr"] for s in ent["sites"]
                  if s.get("check") == "MATCH" and s["status"] == "honest" and not s["tricks"]]
        rows.append({"shape": qname, "verdict": ent["verdict"], "verified": len(passed),
                     "sites": len(ent["sites"]), "passed_addrs": passed})
    if args.json:
        print(json.dumps(rows, indent=1))
        return
    print("%-28s %-8s %6s %6s  verified sites" % ("shape", "verdict", "verif", "cand"))
    for r in rows:
        print("%-28s %-8s %6d %6d  %s" % (r["shape"], r["verdict"], r["verified"], r["sites"],
                                          " ".join(r["passed_addrs"][:8])))
    fails = [r for r in rows if r["verdict"] != "PASS"]
    if fails:
        print("NEXT  python tools/shape_verify.py verify --shape %s   # re-check failing shapes" % fails[0]["shape"])
    else:
        print("NEXT  python tools/shape_verify.py lessons --write   # refresh the LESSONS.md evidence block")


# ------------------------------------------------------------------- lessons

def render_block(report):
    lines = [BLOCK_BEGIN,
             "## Admitted-shape verification (generated by `tools/shape_verify.py lessons --write`; do not hand-edit)",
             "",
             "Protocol: every shape in `shared/include/albw_shapes.h` must be byte-exact",
             "(`fn.py check` -> `RESULT: MATCH`) at **>= %d distinct registered call sites**" % report.get("min_sites", MIN_SITES),
             "and honest there (no forbidden tricks). One verified site is not enough — a",
             "shape verified once can silently be wrong in its variants; the sites below",
             "are the evidence. Report: `shared/shape_verification.json`",
             "(verifier %s, updated %s)." % (report.get("verifier") or "unverified", report.get("updated") or "-"),
             "",
             "| Shape | Verdict | Verified call sites |",
             "|---|---|---|"]
    for qname, ent in sorted(report.get("shapes", {}).items()):
        verdict = ent.get("verdict") or verdict_of(ent)
        passed = [s for s in ent["sites"]
                  if s.get("check") == "MATCH" and s["status"] == "honest" and not s["tricks"]]
        n_reloc = sum(1 for s in ent["sites"] if (s.get("check") or "").startswith("NO MATCH (reloc)"))
        n_checked = sum(1 for s in ent["sites"] if s.get("check"))
        note = ""
        if verdict != "PASS" and n_reloc:
            note = "; %d/%d checked fail only on unproved mangled-name relocations" % (n_reloc, n_checked)
        site_txt = ", ".join("`%s` (%s)" % (s["addr"], s["path"]) for s in passed[:8])
        if len(passed) > 8:
            site_txt += ", ... (%d total)" % len(passed)
        lines.append("| `%s` | %s (%d/%d sites byte-exact)%s | %s |"
                     % (qname, verdict, len(passed), len(ent["sites"]), note, site_txt or "-"))
    lines.append(BLOCK_END)
    return "\n".join(lines) + "\n"


def cmd_lessons(args):
    if not os.path.exists(REPORT):
        sys.exit("no report; run scan first")
    report = read_json(REPORT)
    block = render_block(report)
    text = open(LESSONS, encoding="utf-8").read()
    if args.write:
        if BLOCK_BEGIN in text and BLOCK_END in text:
            pre, rest = text.split(BLOCK_BEGIN, 1)
            _, post = rest.split(BLOCK_END, 1)
            text = pre + block + post
        else:
            text = text.rstrip("\n") + "\n\n" + block
        atomic_write(LESSONS, text)
        print("LESSONS.md block updated")
        return
    if BLOCK_BEGIN in text and BLOCK_END in text:
        cur = text.split(BLOCK_BEGIN, 1)[1].split(BLOCK_END, 1)[0]
        cur = BLOCK_BEGIN + cur + BLOCK_END + "\n"
        if cur == block:
            print("LESSONS.md shape-verification block: current")
            return
    sys.exit("LESSONS.md shape-verification block stale; run python tools/shape_verify.py lessons --write")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan")
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("verify")
    p.add_argument("--sites", type=int, default=DEFAULT_SITES)
    p.add_argument("--shape")
    p.add_argument("--all", action="store_true", help="re-check even PASS shapes")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("report")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_report)
    p = sub.add_parser("lessons")
    p.add_argument("--write", action="store_true")
    p.set_defaults(fn=cmd_lessons)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
