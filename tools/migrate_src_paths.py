#!/usr/bin/env python
"""ST4 re-home: move src/ + src_lifted/ into the module scheme, one commit.

  python tools/migrate_src_paths.py --dry-run   print the mapping, change nothing
  python tools/migrate_src_paths.py --check     verify the tree is fully re-homed
  python tools/migrate_src_paths.py             apply the migration

Scheme (roadmap v3, ST4). The explicit old-prefix -> new-prefix table, applied
to EVERY file under src/ (registered sources and helper headers alike), so
whole subtrees move rigidly; longest old prefix wins:

  old prefix          new prefix      what
  ------------------  --------------  ----------------------------------------
  src/work8/auto/     src/twins/      auto batches (worklist AUTO_DIR + auto_* generators)
  src/work<N>/        src/game/       module = the old subdir under work<N>
  (sead override)     src/sead/       L0 census rule: a sead/nn/CTRSDK symbol at the
                                      function's own start or inside its range
                                      (tools/census.py sead_named_map over shared/symbols.jsonl)
  src_lifted/         src_lifted/<class>/<basename>   mirrors the scheme

Local `#include "..."` lines that resolve into the moved tree are rebased to
the target's new location (same mechanism as worklist.rebase_includes), so
compilation is unaffected; includes that never resolved file-relative (they
use the -I shared/include fallback or are dead) are left byte-identical.
Everything else is semantics-preserving by construction: every functions.json
entry keeps every field except "path", the same old->new map is applied to the
site paths in shared/shape_verification.json (oracle checks preserved, never
re-derived), and afterwards the generated artifacts that pin ledger paths are
refreshed with the tools that own them: `tools/census.py --write`
(shared/census.json + docs/census.md) and `tools/shape_verify.py lessons --write`
(LESSONS.md block).

Verified by: tests/test_migrate_src_paths.py, `python tools/audit.py`,
`python tools/census.py check`, `python tools/shape_verify.py lessons`,
`tools/fn.py check` on rebased sources, and the rebuild gate
`tools/rebuild_check.py` (EXACT MATCH) on the new tree.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import ROOT, atomic_write, read_json, write_json  # noqa: E402
import audit  # noqa: E402
import census  # noqa: E402

# Explicit old-prefix -> new-prefix table. Longest old prefix wins.
# Campaign trees re-home to src/game/<module>/ with module = the old subdir
# under work<N> (ds7, gpt15, agent1, ...); the auto batch re-homes to src/twins/.
PREFIX_TABLE = (
    ("src/work8/auto/", "src/twins/"),  # auto batch root (worklist.AUTO_DIR)
    ("src/work/", "src/game/"),
    ("src/work4/", "src/game/"),
    ("src/work5/", "src/game/"),
    ("src/work6/", "src/game/"),
    ("src/work7/", "src/game/"),
    ("src/work8/", "src/game/"),
)
SEAD_ROOT = "src/sead/"
LIFTED_ROOT = "src_lifted/"
AUTO_BASENAME_RE = re.compile(r"auto_[0-9a-fA-F]{8}_\d+\.(c|cpp)$")
NEW_ROOTS = ("src/game/", "src/sead/", "src/twins/",
             "src_lifted/game/", "src_lifted/sead/", "src_lifted/twins/")
SHAPES_JSON = os.path.join("shared", "shape_verification.json")
INCLUDE_RE = re.compile(r'^(\s*#\s*include\s*")([^"]+)(")', re.M)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sead_addr_set(root, data):
    """Addrs whose own start or in-range symbol is sead/nn/CTRSDK — exactly the
    L0 census rule (census.sead_named_map), applied to every pathed entry."""
    starts = read_json(os.path.join(root, "funcs.json"))["starts"]
    sizes = census.function_sizes(starts)
    symbols = census.load_symbols(os.path.join(root, "shared", "symbols.jsonl"))
    items = []
    for key, ent in data.items():
        if not ent.get("path"):
            continue
        addr = int(key, 16)
        items.append((addr, sizes.get(addr, 0), ent, ent.get("status")))
    return set(census.sead_named_map(items, symbols))


def strip_work_root(path):
    """src/work<N>/rest -> rest (the module subtree)."""
    parts = path.split("/")
    if len(parts) < 3 or parts[0] != "src" or not parts[1].startswith("work"):
        raise ValueError("not a campaign-tree path: %s" % path)
    return "/".join(parts[2:])


def classify(path, addrs, sead_addrs):
    """old path -> (new path, class). One class per file, first rule wins:
    sead symbol rule (registered files), then the explicit prefix table,
    then auto-named stragglers."""
    if any(path.startswith(r) for r in NEW_ROOTS):
        return path, "done"  # already migrated; idempotent
    if path.startswith(LIFTED_ROOT):
        cls = "sead" if any(a in sead_addrs for a in addrs) else "game"
        return "%s%s/%s" % (LIFTED_ROOT, cls, path.rsplit("/", 1)[1]), cls
    if addrs and any(a in sead_addrs for a in addrs):
        return SEAD_ROOT + strip_work_root(path), "sead"
    for old_pre, new_pre in PREFIX_TABLE:
        if path.startswith(old_pre):
            return new_pre + path[len(old_pre):], "twins" if new_pre == "src/twins/" else "game"
    if AUTO_BASENAME_RE.search(path):
        return "src/twins/" + path.rsplit("/", 1)[1], "twins"
    raise ValueError("no table entry matches path: %s" % path)


def build_mapping(root):
    """old path -> new path for every file on disk under src/ + src_lifted/."""
    data = read_json(os.path.join(root, "functions.json"))
    sead_addrs = sead_addr_set(root, data)
    path2addrs = {}
    for key, ent in data.items():
        if ent.get("path"):
            path2addrs.setdefault(ent["path"], []).append(int(key, 16))
    mapping, classes = {}, {}
    for top in ("src", "src_lifted"):
        base = os.path.join(root, top)
        if not os.path.isdir(base):
            continue
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in filenames:
                full = os.path.join(dirpath, name)
                old = os.path.relpath(full, root)
                new, cls = classify(old, path2addrs.get(old, []), sead_addrs)
                if new in mapping.values():
                    raise ValueError("collision: %s -> %s already produced" % (old, new))
                mapping[old] = new
                classes[new] = cls
    return data, mapping, classes


def rebase_includes(root, mapping):
    """Rewrite local quoted includes that resolve into the moved tree to the
    target's new relative location. Includes that did not resolve file-relative
    before (bare names via -I, dead code) are left byte-identical.
    Returns (set of files whose text changed, number of include lines)."""
    moved = set(mapping)
    changed_files, n_incs = set(), 0
    for old, new in sorted(mapping.items()):
        full = os.path.join(root, new)
        with open(full, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        out, changed = [], False

        def fix(m):
            nonlocal changed, n_incs
            head, inc, tail = m.group(1), m.group(2), m.group(3)
            tgt = os.path.normpath(os.path.join(os.path.dirname(old), inc))
            if tgt not in moved:
                return m.group(0)  # not into the moved tree: bare names and -I / dead includes stay
            new_tgt = mapping[tgt]
            new_inc = os.path.relpath(new_tgt, os.path.dirname(new))
            n_incs += 1
            changed = True
            return head + new_inc + tail

        out = INCLUDE_RE.sub(fix, text)
        if changed:
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(out)
            changed_files.add(new)
    return changed_files, n_incs


def rewrite_ledger(root, data, mapping):
    for ent in data.values():
        if ent.get("path"):
            ent["path"] = mapping[ent["path"]]
    atomic_write(os.path.join(root, "functions.json"), audit.canonical_bytes(data))


def rewrite_shape_sites(root, mapping):
    """Apply the same old->new map to recorded site paths, preserving oracle
    checks (never re-derived)."""
    path = os.path.join(root, SHAPES_JSON)
    if not os.path.exists(path):
        return 0
    report = read_json(path)
    n = 0
    for shape in report.get("shapes", {}).values():
        for site in shape.get("sites", []):
            p = site.get("path")
            if p in mapping:
                site["path"] = mapping[p]
                n += 1
            elif p and not any(p.startswith(r) for r in NEW_ROOTS):
                raise ValueError("site path not covered by the mapping: %s" % p)
    write_json(path, report, canonical=True)
    return n


def regen_generated(root):
    """Refresh the generated artifacts that pin ledger paths, using the tools
    that own them."""
    tools = os.path.join(root, "tools")
    for args in (["census.py", "--write"], ["shape_verify.py", "lessons", "--write"]):
        r = subprocess.run([sys.executable, os.path.join(tools, args[0])] + args[1:],
                           cwd=root, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stdout + r.stderr)
            raise SystemExit("regen failed: %s" % " ".join(args))


def apply_migration(root, regen=True):
    data, mapping, classes = build_mapping(root)
    pending = {o: n for o, n in mapping.items() if o != n}
    if not pending:
        print("nothing to migrate: tree already re-homed")
        return
    use_git = os.path.isdir(os.path.join(root, ".git"))
    before = {old: sha256_file(os.path.join(root, old)) for old in pending}
    stats_before = audit.stats(data)
    for old, new in sorted(pending.items()):
        dest = os.path.join(root, new)
        if os.path.exists(dest):
            raise SystemExit("destination already exists: %s" % new)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if use_git:
            subprocess.run(["git", "-C", root, "mv", old, new], check=True,
                           capture_output=True)
        else:
            shutil.move(os.path.join(root, old), dest)
    for top in ("src", "src_lifted"):  # prune emptied campaign dirs, bottom-up
        base = os.path.join(root, top)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, _f in os.walk(base, topdown=False):
            if dirpath == base:
                continue
            try:
                os.rmdir(dirpath)
            except OSError:
                pass
    changed_files, n_incs = rebase_includes(root, pending)
    for old, new in pending.items():
        if new not in changed_files and sha256_file(os.path.join(root, new)) != before[old]:
            raise SystemExit("content changed across move (not an include rebase): %s -> %s" % (old, new))
    rewrite_ledger(root, data, pending)
    n_sites = rewrite_shape_sites(root, pending)
    if regen:
        regen_generated(root)
    data2 = read_json(os.path.join(root, "functions.json"))
    if audit.stats(data2) != stats_before:
        raise SystemExit("ledger stats changed — migration is not semantics-preserving")
    counts = {}
    for cls in classes.values():
        counts[cls] = counts.get(cls, 0) + 1
    print("migrated %d files: %s" % (len(pending), ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    print("rebased %d include line(s) in %d file(s)" % (n_incs, len(changed_files)))
    print("rewrote %d site paths in %s" % (n_sites, SHAPES_JSON))
    print("ledger stats unchanged: %d entries, honest=%d hack=%d lifted=%d"
          % (len(data2), stats_before["honest"], stats_before["hack"], stats_before["lifted"]))


def check(root):
    """Verify the tree is fully re-homed: every registered path under a new
    root and present on disk, and no campaign-tree files left behind."""
    data = read_json(os.path.join(root, "functions.json"))
    pathed = [ent["path"] for ent in data.values() if ent.get("path")]
    bad = [p for p in pathed if not any(p.startswith(r) for r in NEW_ROOTS)]
    missing = [p for p in pathed if not os.path.isfile(os.path.join(root, p))]
    leftover = []
    for top in ("src", "src_lifted"):
        base = os.path.join(root, top)
        if not os.path.isdir(base):
            continue
        for dirpath, _d, filenames in os.walk(base):
            for name in filenames:
                p = os.path.relpath(os.path.join(dirpath, name), root)
                if not any(p.startswith(r) for r in NEW_ROOTS):
                    leftover.append(p)
    if bad:
        print("NOT migrated: %d registered paths outside the new roots, e.g. %s" % (len(bad), bad[0]))
    if missing:
        print("MISSING: %d registered paths not on disk, e.g. %s" % (len(missing), missing[0]))
    if leftover:
        print("LEFTOVER: %d files outside the new roots, e.g. %s" % (len(leftover), leftover[0]))
    ok = not bad and not missing and not leftover
    print("paths: %d registered, %s" % (len(pathed), "all re-homed" if ok else "incomplete"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="print the mapping, change nothing")
    ap.add_argument("--check", action="store_true", help="verify the tree is fully re-homed")
    args = ap.parse_args()
    if args.check:
        return check(ROOT)
    data, mapping, classes = build_mapping(ROOT)
    if args.dry_run:
        pending = {o: n for o, n in mapping.items() if o != n}
        counts = {}
        for old, new in pending.items():
            counts[classes[new]] = counts.get(classes[new], 0) + 1
        print("%d files to migrate: %s" % (len(pending), ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
        for old in sorted(pending)[:10]:
            print("  %s -> %s" % (old, pending[old]))
        if len(pending) > 10:
            print("  ... (%d more)" % (len(pending) - 10))
        return 0
    apply_migration(ROOT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
