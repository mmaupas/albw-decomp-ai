"""Recipe corpus: machine-checkable compiler-physics entries (automation step 3).

  python tools/recipes.py add <id> --positive "shape" --source "construct" \
      [--flags "..." --requires a,b --refs LESSONS.md#x,00102FB4]
  python tools/recipes.py add <id> --negative --shape "shape" --refs ...
  python tools/recipes.py query <mnemonic-signature>   # e.g. "strd stm str"
  python tools/recipes.py list [--negative]

Positive recipes map a target shape -> the source construct + flags that
produced an honest match. Negative recipes are HARD SKIPS: shapes proven
unproducible from armcc 4.1 C, checked before any compile budget is spent.

Corpus file: shared/recipes.json (mirrored human-readable in docs/LESSONS.md).
"""
import argparse
import json
import os
import sys

from common import file_lock, read_json, write_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "shared", "recipes.json")


def load():
    if not os.path.exists(CORPUS):
        return []
    return read_json(CORPUS)


def save(recipes):
    write_json(CORPUS, recipes, canonical=True)


def add(args):
    with file_lock(os.path.join(ROOT, "logs", "recipes.lock")):
        _add(args)


def _add(args):
    if any(r["id"] == args.id for r in load()):
        sys.exit("recipe id already exists: %s" % args.id)
    r = {"id": args.id}
    if args.negative:
        r["kind"] = "negative"
        r["shape"] = args.shape
    else:
        if not (args.shape and args.source):
            sys.exit("--positive needs --shape and --source")
        r["kind"] = "positive"
        r["shape"] = args.shape
        r["source"] = args.source
        r["flags"] = args.flags
    if args.requires:
        r["requires"] = args.requires.split(",")
    if args.refs:
        r["refs"] = args.refs.split(",")
    recipes = load() + [r]
    save(recipes)
    print("added %s (%d recipes)" % (r["id"], len(recipes)))


def query(args):
    sig = args.signature.lower().split()
    hits = []
    for r in load():
        text = (r.get("shape", "") + " " + r.get("source", "")).lower()
        if any(t in text for t in sig):
            hits.append(r)
    if args.json:
        print(json.dumps(hits))
        return
    for r in hits:
        print("[%s] %s" % (r["kind"], r["id"]))
        print("  shape:   %s" % r.get("shape", ""))
        if "source" in r:
            print("  source:  %s" % r["source"])
            print("  flags:   %s" % r.get("flags", "default"))
        if "requires" in r:
            print("  requires: %s" % ", ".join(r["requires"]))
        if "refs" in r:
            print("  refs:    %s" % ", ".join(r["refs"]))
    if not hits:
        print("no recipes match; sources of prior knowledge: docs/LESSONS.md")


def do_list(args):
    for r in load():
        if args.negative and r["kind"] != "negative":
            continue
        print("[%-8s] %-28s %s" % (r["kind"], r["id"], r.get("shape", "")[:90]))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("id")
    a.add_argument("--positive", action="store_true")
    a.add_argument("--negative", action="store_true")
    a.add_argument("--shape")
    a.add_argument("--source")
    a.add_argument("--flags", default="default")
    a.add_argument("--requires")
    a.add_argument("--refs")
    a.set_defaults(fn=add)
    q = sub.add_parser("query")
    q.add_argument("signature")
    q.add_argument("--json", action="store_true")
    q.set_defaults(fn=query)
    l = sub.add_parser("list")
    l.add_argument("--negative", action="store_true")
    l.set_defaults(fn=do_list)
    args = p.parse_args()
    args.fn(args)
