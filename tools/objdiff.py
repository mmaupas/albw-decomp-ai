#!/usr/bin/env python3
"""Thin, stdlib-only wrapper around objdiff-cli (object-level, data-aware diffing).

  python3 tools/objdiff.py diff <base-obj> <target-obj> [--symbol NAME] [--json]
  python3 tools/objdiff.py units <obj> [--json]

objdiff-cli is NOT committed and is never downloaded at build time. Run
`python3 tools/setup_objdiff.py` once (pinned release, SHA-256 verified) to
place it at tools/bin/objdiff-cli (gitignored). Without the binary - or
without the object files - every command prints the exact setup/phone command
and exits 2, the same degradation convention as tools/lift.py.

`diff` drives objdiff-cli's one-shot mode (`diff -2 <base> -1 <target> -o -
--format json`) and re-emits the tool's own JSON; if the output resists
parsing, a structured passthrough {tool, command, returncode, stdout, stderr}
is emitted instead. `units` diffs the object against itself and lists its
units (symbols) and sections with sizes and match percentages. ARM objects
from armcc are supported by objdiff-cli's architecture detection, so this is
the machine-readable view for multi-function objects and pool-data diffs.
"""
import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_REL = os.path.join("tools", "bin", "objdiff-cli")
TIMEOUT = 600

SETUP_HINT = """objdiff-cli is not installed (or an object file is missing){reason}.
One-time setup - downloads the PINNED objdiff-cli v3.8.3 release (SHA-256
verified) into the gitignored tools/bin/; never committed, never fetched at
build time:
  python3 tools/setup_objdiff.py                          # this host
  python3 tools/setup_objdiff.py --target linux-aarch64   # the phone (Termux)
Then, with armcc-built objects (e.g. under logs/check/ on the phone):
  python3 tools/objdiff.py units <object> --json
  python3 tools/objdiff.py diff <base-obj> <target-obj> --json
See README.md 'Object-level diffing (objdiff-cli)'."""


def binary_path(root=None):
    path = os.path.join(root or ROOT, BIN_REL)
    if os.name == "nt" and not path.endswith(".exe"):
        path += ".exe"
    return path


def run_cli(args, root=None):
    """Run the installed objdiff-cli; (returncode, stdout, stderr) or None when
    the binary is absent."""
    binary = binary_path(root)
    if not os.path.isfile(binary):
        return None
    proc = subprocess.run([binary] + list(args), capture_output=True, text=True,
                          timeout=TIMEOUT)
    return proc.returncode, proc.stdout, proc.stderr


def parse_output(out):
    """Parse the tool's own JSON; None when the output resists parsing."""
    try:
        return json.loads(out)
    except ValueError:
        return None


def passthrough(argv, rc, out, err):
    return {"tool": "objdiff-cli", "command": argv, "returncode": rc,
            "stdout": out, "stderr": err}


def missing(reason):
    print(SETUP_HINT.format(reason=": " + reason if reason else ""))
    return 2


def cmd_diff(base, target, symbol=None, as_json=False, root=None):
    if not os.path.isfile(binary_path(root)):
        return missing("binary tools/bin/objdiff-cli")
    for path in (base, target):
        if not os.path.isfile(path):
            return missing("object file %s" % path)
    argv = ["diff", "-2", base, "-1", target, "-o", "-", "--format", "json"]
    if symbol:
        argv.append(symbol)
    res = run_cli(argv, root)
    if res is None:
        return missing("binary tools/bin/objdiff-cli")
    rc, out, err = res
    parsed = parse_output(out)
    if as_json:
        print(json.dumps(parsed if parsed is not None else passthrough(argv, rc, out, err)))
    elif parsed is not None:
        print_diff_text(parsed, base, target, symbol)
    else:
        print(out)
        if err:
            print(err, file=sys.stderr)
    return 0 if rc == 0 else 1


def print_diff_text(parsed, base, target, symbol):
    print("objdiff-cli diff: base=%s target=%s%s" % (
        base, target, " symbol=%s" % symbol if symbol else ""))
    for side in ("left", "right"):
        obj = parsed.get(side) or {}
        sections = obj.get("sections") or []
        if sections:
            print("  %s sections:" % side)
            for sec in sections:
                line = "    %-14s %-14s size=%s" % (sec.get("name", "?"), sec.get("kind", ""),
                                                    sec.get("size", "?"))
                if "match_percent" in sec:
                    line += " match=%.2f%%" % float(sec["match_percent"])
                if sec.get("data_diff"):
                    line += " data_diff=%d block(s)" % len(sec["data_diff"])
                print(line)
        for sym in obj.get("symbols") or []:
            if sym.get("kind") != "SYMBOL_FUNCTION":
                continue
            line = "  %s %-24s size=%s" % (side, sym.get("name", "?"), sym.get("size", "?"))
            if "match_percent" in sym:
                line += " match=%.2f%%" % float(sym["match_percent"])
            print(line)


def extract_units(parsed, obj):
    """Unit-level view of one object from a self-diff: symbols + sections."""
    units, sections = [], []
    left = parsed.get("left") or {}
    for sym in left.get("symbols") or []:
        entry = {"name": sym.get("name", "?"), "kind": sym.get("kind", "")}
        if sym.get("size") is not None:
            entry["size"] = int(sym["size"])
        if sym.get("match_percent") is not None:
            entry["match_percent"] = float(sym["match_percent"])
        units.append(entry)
    for sec in left.get("sections") or []:
        entry = {"name": sec.get("name", "?"), "kind": sec.get("kind", "")}
        if sec.get("size") is not None:
            entry["size"] = int(sec["size"])
        if sec.get("match_percent") is not None:
            entry["match_percent"] = float(sec["match_percent"])
        if sec.get("data_diff"):
            entry["data_diff_blocks"] = len(sec["data_diff"])
        sections.append(entry)
    return {"object": obj, "units": units, "sections": sections}


def cmd_units(obj, as_json=False, root=None):
    if not os.path.isfile(binary_path(root)):
        return missing("binary tools/bin/objdiff-cli")
    if not os.path.isfile(obj):
        return missing("object file %s" % obj)
    argv = ["diff", "-2", obj, "-1", obj, "-o", "-", "--format", "json"]
    res = run_cli(argv, root)
    if res is None:
        return missing("binary tools/bin/objdiff-cli")
    rc, out, err = res
    parsed = parse_output(out)
    if as_json:
        if parsed is not None:
            print(json.dumps(extract_units(parsed, obj)))
        else:
            print(json.dumps({"object": obj,
                              "raw": passthrough(argv, rc, out, err)}))
    elif parsed is not None:
        view = extract_units(parsed, obj)
        print("units in %s:" % obj)
        for unit in view["units"]:
            line = "  %-28s %-18s size=%s" % (unit["name"], unit["kind"],
                                              unit.get("size", "?"))
            if "match_percent" in unit:
                line += " match=%.2f%%" % unit["match_percent"]
            print(line)
        for sec in view["sections"]:
            if sec.get("kind", "").startswith("SECTION"):
                line = "  [section] %-14s size=%s" % (sec["name"], sec.get("size", "?"))
                if "match_percent" in sec:
                    line += " match=%.2f%%" % sec["match_percent"]
                if sec.get("data_diff_blocks"):
                    line += " data_diff=%d block(s)" % sec["data_diff_blocks"]
                print(line)
    else:
        print(out)
        if err:
            print(err, file=sys.stderr)
    return 0 if rc == 0 else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff", help="diff two object files (base vs target)")
    d.add_argument("base")
    d.add_argument("target")
    d.add_argument("--symbol", default=None, help="restrict to one symbol/unit")
    d.add_argument("--json", action="store_true")
    u = sub.add_parser("units", help="list the units (symbols/sections) of one object")
    u.add_argument("obj")
    u.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd == "diff":
        return cmd_diff(args.base, args.target, symbol=args.symbol, as_json=args.json)
    return cmd_units(args.obj, as_json=args.json)


if __name__ == "__main__":
    sys.exit(main())
