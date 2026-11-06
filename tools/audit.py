"""Audit invariants of the published data, without code.bin or armcc.

  python tools/audit.py [--json]
  python tools/audit.py stats [--json]

Checks (all offline, all read-only):
  keys            functions.json keys are 8-digit uppercase hex, zero-padded
  schema          status is one of the six known values; honest/hack entries
                  carry path+cc; hack carries non-empty hack_reasons;
                  honest carries empty hack_reasons; every other status
                  carries no path
  paths           every recorded path exists inside the repo and is tracked
                  by git
  format          functions.json matches its canonical dump (indent=1,
                  sort_keys=True, every line lstripped) so future edits
                  produce minimal diffs
  hacks           honest sources contain none of the textually detectable
                  forbidden tricks (weak, __schedule_barrier, asm, perm_t,
                  32-bit no-op masks); hack_reasons use the known vocabulary
  crossref        every functions.json address is a known start in funcs.json

`stats` recomputes the README status table and hack-reason counts from
functions.json, so the README never needs hand-updating arithmetic again.
"""
import argparse
from collections import Counter
import json
import os
import re
import subprocess
import sys

from common import TEXT_SIZE, TEXT_START, atomic_write, read_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STATUSES = ("honest", "hack", "no_source", "excluded", "excluded_library", "interior_address")
MATCHED = ("honest", "hack")
REASONS = ("weak", "__schedule_barrier", "asm", "identical_arms", "perm_t",
           "dummy_local", "volatile_dummy", "nop_mask", "oob_local")

TRICK_PATTERNS = (
    ("weak", re.compile(r"__attribute__\s*\(\((?:[^()]|\([^()]*\))*?\b(?:weak|__weak__)\b|\b__weak\b")),
    ("__schedule_barrier", re.compile(r"__schedule_barrier")),
    ("asm", re.compile(r"\b(?:__)?asm\b")),
    ("perm_t", re.compile(r"\bperm_t\d*\b")),
    ("nop_mask", re.compile(r"&\s*0[xX][fF]{8}\b|\&\s*0[fF]{8}\b")),
)

HEX_KEY = re.compile(r"\A[0-9A-F]{8}\Z")


def canonical_bytes(data):
    return "\n".join(l.lstrip() for l in json.dumps(data, indent=1, sort_keys=True).splitlines())


def trick_reasons(text):
    """Detect obvious forbidden constructs, ignoring comments and literals."""
    code = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  " ", text, flags=re.DOTALL)
    return [name for name, pattern in TRICK_PATTERNS if pattern.search(code)]


def source_path(path):
    """Return a contained, repo-relative source path; reject symlink escapes."""
    if os.path.isabs(path):
        raise ValueError("source path must be repository-relative")
    full = os.path.realpath(os.path.join(ROOT, path))
    if os.path.commonpath([os.path.realpath(ROOT), full]) != os.path.realpath(ROOT):
        raise ValueError("source path escapes repository")
    return full


def load():
    with open(os.path.join(ROOT, "functions.json"), encoding="utf-8") as fh:
        return json.load(fh)


def check_all():
    errors, warnings = [], []
    data = load()
    with open(os.path.join(ROOT, "functions.json"), encoding="utf-8") as stream:
        raw = stream.read()

    if raw != canonical_bytes(data):
        errors.append("format: functions.json is not in its canonical dump (indent=1, sort_keys=True, flat left margin)")

    starts = set(read_json(os.path.join(ROOT, "funcs.json"))["starts"])
    tracked = set(subprocess.run(
        ["git", "-C", ROOT, "ls-files"], capture_output=True, text=True,
        check=True).stdout.splitlines())

    for addr, ent in data.items():
        if not HEX_KEY.match(addr):
            errors.append("keys: %r is not an 8-digit uppercase hex key" % addr)
            continue
        if not isinstance(ent, dict):
            errors.append("schema: %s is not an object" % addr)
            continue
        status = ent.get("status")
        if status not in STATUSES:
            errors.append("schema: %s has unknown status %r" % (addr, status))
            continue
        if status != "interior_address" and int(addr, 16) not in starts:
            errors.append("crossref: %s is not a start in funcs.json" % addr)
        path = ent.get("path")
        if status in MATCHED:
            if not path:
                errors.append("schema: %s is %s but has no source path" % (addr, status))
            elif not ent.get("cc"):
                errors.append("schema: %s has a path but no cc" % addr)
        else:
            if path:
                errors.append("schema: %s is %s but carries a path" % (addr, status))
        if status == "hack" and not ent.get("hack_reasons"):
            errors.append("schema: %s is a hack with no hack_reasons" % addr)
        if status == "honest" and ent.get("hack_reasons"):
            errors.append("schema: %s is honest but lists hack_reasons %r" % (addr, ent["hack_reasons"]))
        for reason in ent.get("hack_reasons", []):
            if reason not in REASONS:
                warnings.append("hacks: %s uses unknown hack reason %r" % (addr, reason))
        if path:
            try:
                full = source_path(path)
            except ValueError as exc:
                errors.append("paths: %s -> %s: %s" % (addr, path, exc))
                continue
            if not os.path.isfile(full):
                errors.append("paths: %s -> %s does not exist" % (addr, path))
            elif path not in tracked:
                errors.append("paths: %s -> %s is not tracked by git" % (addr, path))

    n_honest = sum(1 for v in data.values() if isinstance(v, dict) and v.get("status") == "honest")
    for addr, ent in data.items():
        if not isinstance(ent, dict) or ent.get("status") != "honest" or not ent.get("path"):
            continue
        try:
            with open(source_path(ent["path"]), encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, ValueError) as exc:
            errors.append("hacks: %s -> %s unreadable: %s" % (addr, ent["path"], exc))
            continue
        for name in trick_reasons(text):
            errors.append("hacks: %s is honest but %s appears in %s" % (addr, name, ent["path"]))
    return data, errors, warnings, n_honest


def stats(data):
    starts = read_json(os.path.join(ROOT, "funcs.json"))["starts"]
    total = len(starts)
    by_status = Counter(data.get("%08X" % addr, {}).get("status", "unmatched") for addr in starts)
    byte_counts = Counter()
    for i, addr in enumerate(starts):
        end = starts[i + 1] if i + 1 < total else TEXT_START + TEXT_SIZE
        byte_counts[data.get("%08X" % addr, {}).get("status", "unmatched")] += end - addr
    matched_src = by_status["honest"] + by_status["hack"]
    reasons = Counter(r for v in data.values() if v.get("status") == "hack" for r in v.get("hack_reasons", []))
    return {
        "total_functions": total,
        "matched_source_included": matched_src,
        "matched_source_included_pct": round(100.0 * matched_src / total, 1),
        "honest": by_status["honest"],
        "honest_pct": round(100.0 * by_status["honest"] / total, 1),
        "hack": by_status["hack"],
        "hack_pct": round(100.0 * by_status["hack"] / total, 1),
        "no_source": by_status["no_source"],
        "excluded": by_status["excluded"],
        "excluded_library": by_status["excluded_library"],
        "interior_address": sum(v.get("status") == "interior_address" for v in data.values()),
        "unmatched": by_status["unmatched"],
        "remaining_honest": total - by_status["honest"] - by_status["excluded"] - by_status["excluded_library"],
        "text_bytes": TEXT_SIZE,
        "bytes_by_status": dict(byte_counts),
        "hack_reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
    }


def readme_blocks(out):
    """Generate both summaries from the same counts and .text address ranges."""
    total, text_bytes = out["total_functions"], out["text_bytes"]
    rows = [("Matched, source included", out["matched_source_included"],
             out["bytes_by_status"].get("honest", 0) + out["bytes_by_status"].get("hack", 0))]
    for label, status in (("of which honest (no hack)", "honest"),
                          ("of which hack", "hack"),
                          ("Earlier match, source not included", "no_source"),
                          ("Not matched yet", "unmatched"),
                          ("Excluded library", "excluded_library"),
                          ("Other exclusions", "excluded")):
        if out.get(status, 0):
            rows.append((label, out[status], out["bytes_by_status"].get(status, 0)))
    lines = ["| | Functions | Share of {:,} | .text bytes | Share of {:,} B |".format(total, text_bytes),
             "|---|---:|---:|---:|---:|"]
    for label, count, size in rows:
        lines.append("| {} | {:,} | {:.1f}% | {:,} | {:.1f}% |".format(
            label, count, 100 * count / total, size, 100 * size / text_bytes))
    lines += ["", "Remaining for an honest decompilation (excluding libraries): **{:,}** functions.".format(out["remaining_honest"]),
              "", "Sizes use consecutive starts in `funcs.json` within `.text` (`0x{:X}`–`0x{:X}`), not the whole binary.".format(TEXT_START, TEXT_START + TEXT_SIZE),
              "{} interior-address entries are not counted as separate functions.".format(out["interior_address"]),
              "", "Hack reasons (a function can have several): " + ", ".join(
                  "{} {}".format(reason, count) for reason, count in out["hack_reasons"].items()) + "."]
    arabic = ("- **وين وصلنا:** {:,} دالة لها مصدر ({:.1f}%)، منها {:,} نظيفة ({:.1f}%) و{:,} بحيل.\n"
              "- **وش باقي:** {:,} دالة غير مطابقة؛ الباقي لتفكيك نظيف، باستثناء المكتبات، {:,} دالة.").format(
                  out["matched_source_included"], out["matched_source_included_pct"],
                  out["honest"], out["honest_pct"], out["hack"], out["unmatched"], out["remaining_honest"])
    return {"status": "\n".join(lines), "arabic-status": arabic}


def update_readme(out, write=False):
    path = os.path.join(ROOT, "README.md")
    with open(path, encoding="utf-8") as stream:
        original = stream.read()
    updated = original
    for name, block in readme_blocks(out).items():
        start, end = "<!-- generated:%s -->" % name, "<!-- /generated:%s -->" % name
        pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
        if len(pattern.findall(updated)) != 1:
            raise ValueError("README needs exactly one generated block: " + name)
        updated = pattern.sub(lambda match: start + "\n" + block + "\n" + end, updated)
    if write:
        atomic_write(path, updated)
    return updated == original


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", choices=("check", "stats", "readme"), default="check")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write", action="store_true", help="refresh README generated blocks")
    args = ap.parse_args()
    if args.write and args.mode != "readme":
        ap.error("--write is only valid with readme")

    data = load()
    if args.mode == "readme":
        current = update_readme(stats(data), write=args.write)
        result = {"current": current or args.write}
        print(json.dumps(result) if args.json else "README: " + ("current" if result["current"] else "stale; run python3 tools/audit.py readme --write"))
        return 0 if result["current"] else 1
    if args.mode == "stats":
        out = stats(data)
        if args.json:
            print(json.dumps(out, indent=1, sort_keys=True))
        else:
            print("Total functions in funcs.json: %d" % out["total_functions"])
            print("Matched, source included:      %d  (%.1f%%)" % (out["matched_source_included"], out["matched_source_included_pct"]))
            print("  honest:                      %d  (%.1f%%)" % (out["honest"], out["honest_pct"]))
            print("  hack:                        %d  (%.1f%%)" % (out["hack"], out["hack_pct"]))
            print("Matched earlier, no source:    %d" % out["no_source"])
            print("Non-redistributable 3rd-party:  %d" % out["excluded"])
            print("Prebuilt middleware/SDK:       %d" % out["excluded_library"])
            print("Interior addresses:            %d" % out["interior_address"])
            print("Hack reasons:")
            for name, cnt in out["hack_reasons"].items():
                print("  %-20s %d" % (name, cnt))
        return 0

    data, errors, warnings, n_honest = check_all()
    if args.json:
        print(json.dumps({
            "functions": len(data),
            "honest": n_honest,
            "errors": errors,
            "warnings": warnings,
        }, indent=1, sort_keys=True))
    else:
        print("Audited %d entries in functions.json" % len(data))
        for e in errors:
            print("ERROR  %s" % e)
        for w in warnings:
            print("WARN   %s" % w)
        print("RESULT: %s (%d error%s, %d warning%s)" % (
            "CLEAN" if not errors else "FAIL",
            len(errors), "" if len(errors) == 1 else "s",
            len(warnings), "" if len(warnings) == 1 else "s"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
