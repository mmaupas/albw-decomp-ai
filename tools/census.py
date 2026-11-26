#!/usr/bin/env python
"""Byte census of every non-matched function (roadmap v3, item L0).

  python tools/census.py [--json] [--image PATH]     full census (default: text summary)
  python tools/census.py pools [--json]             pool table only
  python tools/census.py functions [--pool P] [--json]
  python tools/census.py check                      freshness of shared/census.json + docs/census.md
  python tools/census.py --write                    write the canonical shared/census.json + docs/census.md
  python tools/census.py --write-full [--image PATH] full-mode copies under logs/census/ (needs code.bin)

What this is: the byte-weighted classification of every non-matched function
into named pools, so strategy can be re-derived from data. It answers:
  1. where the unmatched .text bytes live, by class;
  2. which parked wall recipes hold the most bytes (physics-priority ranking);
  3. how big the svc/CTRSDK region is and what excluding it does to the
     honest-bytes share (sibling-project convention).

Size source (canonical, deliberately not reinvented): per-function .text
bytes use the exact accounting tools/audit.py stats() uses for its status
table byte columns — consecutive starts in funcs.json within .text
(0x100000..0x69211C), the last function ending at TEXT_START+TEXT_SIZE.
build_census() reconciles its pool sums against that same per-status byte
table, and the CLI additionally asserts equality with audit.stats().

Matched = audit.MATCHED ("honest", "hack"). Census input = every funcs.json
start whose status is anything else (no entry => "unmatched"), i.e. plain
unmatched + no_source (label source_lost) + excluded_library + lifted +
semantic_match + excluded. interior_address entries are not starts and are
never counted.

Pools (precedence order, first match wins, every function classified once):
  1 lifted                status "lifted" (src_lifted scaffold; still honestly
                          matchable later, but never counted as matched now)
  2 excluded_library      status "excluded_library" (prebuilt middleware/SDK)
  3 source_lost           status "no_source" / label "source_lost"
  4 svc_region            instruction stream contains >= 1 svc (capstone pass
                          over code.bin); per-function svc numbers recorded
  5 parked_recipe         synth.check_negative() over the instruction stream
                          (the negative-recipe corpus shared/recipes.json,
                          ids mirrored in tools/synth.py — the same
                          machine-checkable labels the worklist enforces);
                          per-recipe byte ranking reported
  6 shape_family_residue  function's shapemine motif set (normalized tokens,
                          pool excluded) intersects a PASS shape's verified
                          motif signature (shared/shape_verification.json,
                          verdict via shape_verify.verdict_of, signature via
                          reharvest.shape_motif_signature); per-family bytes
  7 sead_named            the function or a symbol recorded inside its range
                          (shared/symbols.jsonl) carries a sead/nn/CTRSDK
                          name — name-based only, APPROXIMATE, no call-graph
                          guesses
  8 hot_bespoke           top 500 by coverage_rank.py hits, or size > 1 KB and
                          in the top 100 largest census functions
  9 other                 everything else, explicitly counted

Instruction pools (4, 5, 6) plus per-function instruction metadata
(has_svc, has_vfp, has_ldrex_strex, has_ldm_stm) need code.bin + capstone.
Without them they degrade to null, the exact setup hint is printed, and the
command exits 2 (the tools/lift.py convention); every ledger pool still
works. Canonical committed outputs (shared/census.json, docs/census.md) are
the LEDGER-PINNED offline census: deterministic from committed inputs only,
so CI (which has no code.bin) can freshness-check them exactly. The full
census with instruction pools is printed by --json / written by --write-full
on the box that has code.bin.

Determinism: json.dumps(indent=1, sort_keys=True) over input-sha256-pinned
data; no timestamps, no randomness, no sampling (full pass over all census
functions when code.bin is present).
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (BINARY_SHA1, ROOT, TEXT_SIZE, TEXT_START, atomic_write,
                    load_binary, read_json, write_json)  # noqa: E402
import audit  # noqa: E402
import shapemine  # noqa: E402

try:
    from capstone import Cs
except ImportError:
    Cs = None

CODE_BIN = os.path.join(ROOT, "code.bin")
CENSUS_JSON = os.path.join(ROOT, "shared", "census.json")
CENSUS_MD = os.path.join(ROOT, "docs", "census.md")
FULL_DIR = os.path.join(ROOT, "logs", "census")
SYMBOLS = os.path.join(ROOT, "shared", "symbols.jsonl")
SHAPES_JSON = os.path.join(ROOT, "shared", "shape_verification.json")

MATCHED = audit.MATCHED
POOLS = ("lifted", "excluded_library", "source_lost", "svc_region", "parked_recipe",
         "shape_family_residue", "sead_named", "hot_bespoke", "other")
INSTRUCTION_POOLS = ("svc_region", "parked_recipe", "shape_family_residue")
GOAL_SHARE = 0.5
HOT_COVERAGE_TOP = 500
HOT_SIZE_BYTES = 1024
HOT_SIZE_TOP = 100
SEAD_NN_RE = re.compile(r"\bsead\b|\bnn\b|CTRSDK")
DOC_BEGIN = "<!-- generated:census -->"
DOC_END = "<!-- /generated:census -->"

SETUP_HINT = """code.bin/capstone not available in this environment; the instruction pools
(svc_region, parked_recipe, shape_family_residue) and the per-function
instruction metadata are null. All ledger pools are still fully classified.
On the box with your own USA dump (code.bin in the repo root, SHA-1
%s, 6,455,296 bytes) and capstone installed (`uv sync`), run:
  uv run python tools/census.py --json          # full census incl. instruction pools (exit 0)
  uv run python tools/census.py --write-full    # full copies under logs/census/
  python tools/census.py --write                 # refresh canonical ledger-pinned outputs
  python tools/census.py check                   # CI freshness check (offline, always works)""" % BINARY_SHA1

GAP_NOTES = {
    "lifted": "could close the gap: a lifted scaffold is not a match; the function can still be honestly matched later",
    "excluded_library": "cannot close the gap: non-redistributable prebuilt middleware/SDK, excluded from the target by convention",
    "source_lost": "could close the gap: re-derivation target (dna twin + synth); bytes count toward honest once matched",
    "svc_region": "cannot close from C: neg-svc-stub (armcc's __svc is call-shaped; frameless svc stubs are SDK asm) - exclusion candidate, not honestly matchable",
    "parked_recipe": "hard: every recipe here is a proven hard skip under current armcc physics; bytes close only via new source physics, not by retrying",
    "shape_family_residue": "could close the gap: admitting the already byte-verified shape to shared/include unlocks these functions; highest-leverage pool",
    "sead_named": "could close the gap: name-known engine code, ordinary matching work (name-based pool, approximate)",
    "hot_bespoke": "could close the gap: flagship manual targets (top coverage hits / largest functions), highest per-function effort",
    "other": "could close the gap: honest unclassified remainder - an honest large `other` is a result, not a failure",
}
WINNABLE_EXCEPT = ("excluded_library", "svc_region")


def sha256_file(path):
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


def function_sizes(starts, text_start=TEXT_START, text_size=TEXT_SIZE):
    """Per-function .text bytes, audit.stats() convention: consecutive starts,
    last function ends at text_start+text_size. Canonical size source."""
    sizes = {}
    for i, addr in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else text_start + text_size
        sizes[addr] = end - addr
    return sizes


def load_symbols(path=SYMBOLS):
    """addr(int) -> name, latest entry wins (same rule as fn.known_symbols)."""
    out = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    out[int(d["addr"], 16)] = d["name"]
                except (ValueError, KeyError):
                    continue
    return out


def sead_named_map(census_items, symbols, text_start=TEXT_START):
    """addr -> {symbol, symbol_addr} for census functions whose own start or a
    symbol recorded inside their range carries a sead/nn/CTRSDK name.
    Name-based only: approximate by construction."""
    sym_addrs = sorted(symbols)
    out = {}
    for addr, _size, _ent, _st in census_items:
        s, e = addr, addr + _size
        hit = None
        for a in sym_addrs:
            if a < s:
                continue
            if a >= e:
                break
            if SEAD_NN_RE.search(symbols[a]):
                hit = a
                break
        if hit is not None:
            out[addr] = {"symbol": symbols[hit], "symbol_addr": "%08X" % hit}
    return out


def hot_size_map(census_items):
    """size > 1 KB and in the top 100 largest census functions."""
    ranked = sorted(census_items, key=lambda it: (-it[1], it[0]))[:HOT_SIZE_TOP]
    return {addr: {"size_rank": i + 1, "size": size}
            for i, (addr, size, _e, _s) in enumerate(ranked) if size > HOT_SIZE_BYTES}


def hot_coverage_map(census_addrs):
    """Top 500 by coverage hits per tools/coverage_rank.py (full mode only;
    empty when no coverage log / report exists, e.g. offline CI)."""
    import coverage_rank
    import fn
    rows = coverage_rank.load_report()
    hits = coverage_rank.load_coverage([coverage_rank.DEFAULT_COVERAGE])
    if not rows and not hits:
        return {}
    ranked = coverage_rank.rank(rows, hits)[:HOT_COVERAGE_TOP]
    out = {}
    for i, row in enumerate(ranked):
        start = fn.func_range(int(row["addr"], 16))[0]
        if start in census_addrs:
            out[start] = {"coverage_rank": i + 1, "hits": row["hits"],
                          "score": round(row["score"], 6)}
    return out


def scan_instructions(image, addrs):
    """Capstone pass over `image` for the given function starts.

    Reuses the repo machinery end to end: the image is injected into
    fn.CODE so fn.dis1/fn.code_end/fn.rd32 read it, shapemine.func_tokens
    produces the normalized motif tokens (pool excluded), synth.view builds
    the (mnemonic, op) view and synth.check_negative labels negative recipes.
    Returns addr -> {motifs, recipe, has_svc, svc, has_vfp, has_ldrex_strex,
    has_ldm_stm}."""
    import fn
    import synth
    fn.CODE = image
    out = {}
    for addr in sorted(addrs):
        tokens = shapemine.func_tokens(addr)
        _s, _e, ins = synth.view(addr)
        mnemonics = [m.split(".")[0] for m, _o in ins]
        svc = []
        for m, o in ins:
            if m == "svc":
                try:
                    svc.append(int(o.lstrip("#"), 0))
                except ValueError:
                    pass
        out[addr] = {
            "motifs": sorted({shapemine.motif_id(sig) for sig in shapemine.ngrams(tokens)}),
            "recipe": synth.check_negative(ins),
            "has_svc": bool(svc),
            "svc": sorted(set(svc)),
            "has_vfp": any(m.startswith(("vldr", "vstr", "vpush", "vpop", "vldm", "vstm"))
                           for m in mnemonics),
            "has_ldrex_strex": any(m.startswith(("ldrex", "strex")) for m in mnemonics),
            "has_ldm_stm": any(m.startswith(("ldm", "stm")) for m in mnemonics),
        }
    return out


def shape_families(instr, census_addrs, shapes_path=SHAPES_JSON):
    """PASS-shape motif signatures (reharvest machinery) vs census functions.
    Returns addr -> sorted list of PASS shape family names it contains."""
    import reharvest
    from shape_verify import verdict_of
    report = read_json(shapes_path)
    motifs_by_addr = {"%08X" % addr: set(rec["motifs"]) for addr, rec in instr.items()}
    fams = {}
    for qname, ent in sorted(report.get("shapes", {}).items()):
        verdict = ent.get("verdict") or verdict_of(ent)
        if verdict != "PASS":
            continue
        sig, _sites = reharvest.shape_motif_signature(qname, motifs_by_addr)
        if not sig:
            continue
        name = ent.get("name", qname)
        for addr in census_addrs:
            if qname in fams.get(addr, ()):
                continue
            if sig & set(instr[addr]["motifs"]):
                fams.setdefault(addr, []).append(name)
    return {addr: sorted(set(v)) for addr, v in fams.items()}


def classify(addr, size, ent, status, instr, fam_of, sead_of, hot_of):
    """One function -> (pool, evidence). Precedence: POOLS order, first match."""
    if status == "lifted":
        return "lifted", {"status": "lifted", "path": ent.get("path")}
    if status == "excluded_library":
        return "excluded_library", {"status": "excluded_library"}
    if status == "no_source" or ent.get("label") == "source_lost":
        return "source_lost", {"status": status, "label": ent.get("label"),
                               "note": ent.get("note")}
    if instr is not None:
        facts = instr.get(addr)
        if facts:
            if facts["has_svc"]:
                return "svc_region", {"svc": ["0x%X" % n for n in facts["svc"]]}
            if facts["recipe"]:
                return "parked_recipe", {"recipe": facts["recipe"]}
            fams = fam_of.get(addr)
            if fams:
                return "shape_family_residue", {"family": fams[0], "families": fams}
    if addr in sead_of:
        return "sead_named", dict(sead_of[addr], approximate=True)
    if addr in hot_of:
        return "hot_bespoke", hot_of[addr]
    return "other", {}


def build_census(functions, starts, symbols=None, instr=None, fam_of=None, hot=None,
                 mode="offline", input_hashes=None, code_bin_sha1=None,
                 text_start=TEXT_START, text_size=TEXT_SIZE, audit_match=None):
    """Pure census builder. functions: functions.json dict; starts: funcs.json
    starts; instr/fam_of/hot: full-mode instruction data (None => offline).
    Returns the deterministic census dict."""
    sizes = function_sizes(starts, text_start, text_size)
    by_status, bytes_by_status = {}, {}
    census_items = []
    for addr in starts:
        ent = functions.get("%08X" % addr) or {}
        status = ent.get("status", "unmatched")
        by_status[status] = by_status.get(status, 0) + 1
        bytes_by_status[status] = bytes_by_status.get(status, 0) + sizes[addr]
        if status not in MATCHED:
            census_items.append((addr, sizes[addr], ent, status))
    census_addrs = {addr for addr, _s, _e, _st in census_items}
    sead_of = sead_named_map(census_items, symbols or {}, text_start)
    hot_of = dict(hot or {})

    entries = {}
    pool_funcs = {p: 0 for p in POOLS}
    pool_bytes = {p: 0 for p in POOLS}
    for addr, size, ent, status in census_items:
        pool, evidence = classify(addr, size, ent, status, instr, fam_of, sead_of, hot_of)
        pool_funcs[pool] += 1
        pool_bytes[pool] += size
        entry = {"size": size, "status": status, "pool": pool, "evidence": evidence}
        if instr is not None and addr in instr:
            facts = instr[addr]
            entry["instructions"] = {
                "has_svc": facts["has_svc"],
                "svc": ["0x%X" % n for n in facts["svc"]],
                "has_vfp": facts["has_vfp"],
                "has_ldrex_strex": facts["has_ldrex_strex"],
                "has_ldm_stm": facts["has_ldm_stm"],
            }
        entries["%08X" % addr] = entry

    matched_bytes = bytes_by_status.get("honest", 0) + bytes_by_status.get("hack", 0)
    honest_bytes = bytes_by_status.get("honest", 0)
    text_bytes = text_size
    census_bytes = text_bytes - matched_bytes

    pools = {}
    for p in POOLS:
        avail = not (p in INSTRUCTION_POOLS and instr is None)
        detail = None
        if p == "parked_recipe" and instr is not None:
            rec = {}
            for key, e in entries.items():
                if e["pool"] == p:
                    r = e["evidence"]["recipe"]
                    rec.setdefault(r, {"functions": 0, "bytes": 0})
                    rec[r]["functions"] += 1
                    rec[r]["bytes"] += e["size"]
            detail = {"recipes_by_bytes": dict(sorted(rec.items(), key=lambda kv: (-kv[1]["bytes"], kv[0])))}
        elif p == "shape_family_residue" and instr is not None:
            fam = {}
            for key, e in entries.items():
                if e["pool"] == p:
                    f = e["evidence"]["family"]
                    fam.setdefault(f, {"functions": 0, "bytes": 0})
                    fam[f]["functions"] += 1
                    fam[f]["bytes"] += e["size"]
            detail = {"families_by_bytes": dict(sorted(fam.items(), key=lambda kv: (-kv[1]["bytes"], kv[0])))}
        elif p == "svc_region" and instr is not None:
            nums = {}
            for key, e in entries.items():
                if e["pool"] == p:
                    for n in e["evidence"]["svc"]:
                        nums.setdefault(n, {"functions": 0, "bytes": 0})
                        nums[n]["functions"] += 1
                        nums[n]["bytes"] += e["size"]
            detail = {"svc_numbers": dict(sorted(nums.items(), key=lambda kv: (-kv[1]["bytes"], kv[0])))}
        pools[p] = {
            "functions": pool_funcs[p] if avail else None,
            "bytes": pool_bytes[p] if avail else None,
            "share_of_text_pct": (round(100.0 * pool_bytes[p] / text_bytes, 4)
                                  if avail and text_bytes else None),
            "share_of_census_pct": (round(100.0 * pool_bytes[p] / census_bytes, 4)
                                    if avail and census_bytes else None),
            "available": avail,
            "instruction_pool": p in INSTRUCTION_POOLS,
            "gap_note": GAP_NOTES[p],
            "detail": detail,
        }

    goal_bytes = int(text_bytes * GOAL_SHARE) if text_bytes % 2 == 0 else int(text_bytes * GOAL_SHARE + 0.5)
    needed = goal_bytes - honest_bytes
    winnable = [p for p in POOLS if p not in WINNABLE_EXCEPT]
    winnable_bytes = sum(pool_bytes[p] for p in winnable)
    closing, acc = [], 0
    for p in sorted(winnable, key=lambda q: (-pool_bytes[q], q)):
        if acc >= needed:
            break
        closing.append(p)
        acc += pool_bytes[p]
    gap = {
        "honest_bytes_now": honest_bytes,
        "honest_share_of_text_pct": round(100.0 * honest_bytes / text_bytes, 4) if text_bytes else 0.0,
        "goal_share_pct": 100.0 * GOAL_SHARE,
        "goal_honest_bytes": goal_bytes,
        "needed_honest_bytes": needed,
        "matched_bytes_incl_hack": matched_bytes,
        "census_bytes": census_bytes,
        "census_functions": len(census_items),
        "winnable_pools": winnable,
        "winnable_bytes": winnable_bytes,
        "winnable_bytes_note": ("sum over available pools only; instruction pools are null "
                                "in offline mode and contribute 0 here, they are counted in full mode"),
        "closing_set_by_bytes_desc": closing,
        "closing_set_bytes": acc,
        "note": ("pools whose bytes could count toward the +%d honest-byte gap; "
                 "excluded_library and svc_region cannot (non-redistributable / "
                 "not producible from C under neg-svc-stub)" % needed),
    }

    excl_lib_bytes = pool_bytes["excluded_library"]
    svc_bytes = pool_bytes["svc_region"] if instr is not None else None
    exclusion = {
        "convention": "sibling projects exclude prebuilt SDK/library regions from the target",
        "excluded_library_bytes": excl_lib_bytes,
        "svc_region_bytes": svc_bytes,
        "share_vs_full_text": {"honest_bytes": honest_bytes, "target_bytes": text_bytes,
                               "share_pct": round(100.0 * honest_bytes / text_bytes, 4) if text_bytes else 0.0},
        "share_vs_target_minus_excluded_library": {
            "honest_bytes": honest_bytes,
            "target_bytes": text_bytes - excl_lib_bytes,
            "share_pct": round(100.0 * honest_bytes / (text_bytes - excl_lib_bytes), 4) if text_bytes > excl_lib_bytes else None},
    }
    if svc_bytes is not None:
        tgt = text_bytes - excl_lib_bytes - svc_bytes
        exclusion["share_vs_target_minus_svc_and_library"] = {
            "honest_bytes": honest_bytes, "target_bytes": tgt,
            "share_pct": round(100.0 * honest_bytes / tgt, 4) if tgt else None}
    else:
        exclusion["share_vs_target_minus_svc_and_library"] = None

    instr_meta = None
    if instr is not None:
        flags = ("has_svc", "has_vfp", "has_ldrex_strex", "has_ldm_stm")
        instr_meta = {"available": True, "scanned_functions": len(instr)}
        for f in flags:
            addrs = [a for a, rec in instr.items() if rec[f]]
            instr_meta[f] = {"functions": len(addrs),
                             "bytes": sum(sizes.get(a, 0) for a in addrs)}
        instr_meta["svc_functions"] = instr_meta["has_svc"]

    pool_sum = sum(pool_bytes.values())
    census = {
        "schema": "albw-census/1",
        "mode": mode,
        "inputs": input_hashes or {},
        "code_bin_sha1": code_bin_sha1,
        "size_source": "audit.py stats() convention: consecutive funcs.json starts within .text, last ends at TEXT_START+TEXT_SIZE",
        "matched_statuses": list(MATCHED),
        "text": {"start": text_start, "size": text_bytes},
        "totals": {
            "functions": len(starts),
            "text_bytes": text_bytes,
            "bytes_by_status": bytes_by_status,
            "counts_by_status": by_status,
            "matched_bytes": matched_bytes,
            "honest_bytes": honest_bytes,
            "hack_bytes": bytes_by_status.get("hack", 0),
            "census_functions": len(census_items),
            "census_bytes": census_bytes,
        },
        "gap": gap,
        "pools": pools,
        "exclusion": exclusion,
        "instruction_metadata": instr_meta,
        "functions": entries,
        "reconciliation": {
            "sum_of_pool_bytes": pool_sum,
            "text_minus_matched_bytes": text_bytes - matched_bytes,
            "pools_sum_equals_census": pool_sum == text_bytes - matched_bytes,
            "every_function_classified_once": len(entries) == len(census_items),
            "audit_stats_match": audit_match,
        },
    }
    if instr is None:
        census["setup_hint"] = SETUP_HINT
    return census


def load_repo_inputs(image_path=None):
    """Load the committed inputs and (full mode only) run the instruction pass."""
    functions = read_json(os.path.join(ROOT, "functions.json"))
    starts = read_json(os.path.join(ROOT, "funcs.json"))["starts"]
    symbols = load_symbols()
    input_hashes = {
        "functions.json": sha256_file(os.path.join(ROOT, "functions.json")),
        "funcs.json": sha256_file(os.path.join(ROOT, "funcs.json")),
        "shared/symbols.jsonl": sha256_file(SYMBOLS) if os.path.exists(SYMBOLS) else None,
        "shared/recipes.json": sha256_file(os.path.join(ROOT, "shared", "recipes.json")),
        "shared/shape_verification.json": sha256_file(SHAPES_JSON),
    }
    sizes = function_sizes(starts)
    census_addrs = [a for a in starts
                    if (functions.get("%08X" % a) or {}).get("status", "unmatched") not in MATCHED]
    instr = fam_of = None
    hot = {}
    mode = "offline"
    image = None
    if image_path:
        with open(image_path, "rb") as stream:
            image = stream.read()
    elif os.path.exists(CODE_BIN) and Cs is not None:
        image = load_binary(CODE_BIN)
    if image is not None and Cs is not None:
        mode = "full"
        import fn
        fn.CODE = image
        site_addrs = set()
        report = read_json(SHAPES_JSON)
        import reharvest
        for qname in report.get("shapes", {}):
            for a in reharvest.shape_sites(qname):
                site_addrs.add(int(a, 16))
        scan_addrs = sorted(set(census_addrs) | {a for a in site_addrs if a in set(starts)})
        instr = scan_instructions(image, scan_addrs)
        fam_of = shape_families(instr, set(census_addrs))
        hot = hot_coverage_map(set(census_addrs))
    hot = dict(hot)
    for addr, ev in hot_size_map([(a, sizes[a], None, None) for a in census_addrs]).items():
        hot.setdefault(addr, {}).update(ev)
    stats = audit.stats(functions)
    audit_match = (stats["bytes_by_status"] == _census_bytes_by_status(functions, starts)
                   and stats["total_functions"] == len(starts))
    census = build_census(functions, starts, symbols=symbols, instr=instr, fam_of=fam_of,
                          hot=hot, mode=mode, input_hashes=input_hashes,
                          code_bin_sha1=BINARY_SHA1 if image is not None else None,
                          audit_match=audit_match)
    return census


def _census_bytes_by_status(functions, starts):
    sizes = function_sizes(starts)
    out = {}
    for addr in starts:
        st = (functions.get("%08X" % addr) or {}).get("status", "unmatched")
        out[st] = out.get(st, 0) + sizes[addr]
    return out


# --------------------------------------------------------------------- doc

def _fmt_pct(x):
    return "n/a" if x is None else "%.2f%%" % x


def render_doc(census):
    t = census["totals"]
    g = census["gap"]
    lines = []
    lines.append("# Byte census of the non-matched tail (roadmap v3, item L0)")
    lines.append("")
    lines.append("Generated by `python tools/census.py --write` from `functions.json` + `funcs.json` "
                 "(per-function sizes use the `audit.py stats()` consecutive-starts accounting). "
                 "Mode: **%s**%s. Deterministic: input SHA-256 pinned below, no timestamps." % (
                     census["mode"],
                     " — instruction pools null (no code.bin/capstone here); run `uv run python tools/census.py --json` on the box with code.bin for the full census" if census["mode"] == "offline" else ""))
    lines.append("")
    lines.append("Input pins: " + ", ".join("%s `%s`" % (k, (v or "null")[:12]) for k, v in sorted(census["inputs"].items())))
    if census.get("code_bin_sha1"):
        lines.append("code.bin SHA-1: `%s`" % census["code_bin_sha1"])
    lines.append("")
    lines.append("## Ground truth")
    lines.append("")
    lines.append("| | functions | .text bytes |")
    lines.append("|---|---:|---:|")
    lines.append("| Total .text (`0x{:X}`–`0x{:X}`) | {:,} | {:,} |".format(
        census["text"]["start"], census["text"]["start"] + census["text"]["size"],
        t["functions"], t["text_bytes"]))
    lines.append("| Matched (honest+hack) | {:,} | {:,} |".format(
        t["counts_by_status"].get("honest", 0) + t["counts_by_status"].get("hack", 0), t["matched_bytes"]))
    lines.append("| of which honest | {:,} | {:,} |".format(t["counts_by_status"].get("honest", 0), t["honest_bytes"]))
    lines.append("| Census input (everything non-matched) | {:,} | {:,} |".format(t["census_functions"], t["census_bytes"]))
    lines.append("")
    lines.append("## Answer 1 — where the unmatched bytes live, by pool")
    lines.append("")
    lines.append("| Pool | Functions | Bytes | % of .text | % of census | Instruction pool | Could close the 50% gap |")
    lines.append("|---|---:|---:|---:|---:|---|---|")
    for p in POOLS:
        pool = census["pools"][p]
        if not pool["available"]:
            cells = [p, "null", "null", "null", "null", "yes", "n/a (null offline)"]
        else:
            cells = [p, "{:,}".format(pool["functions"]), "{:,}".format(pool["bytes"]),
                     _fmt_pct(pool["share_of_text_pct"]), _fmt_pct(pool["share_of_census_pct"]),
                     "yes" if pool["instruction_pool"] else "no", "see note"]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("Pool gap notes:")
    lines.append("")
    for p in POOLS:
        lines.append("- `%s`: %s" % (p, census["pools"][p]["gap_note"]))
    lines.append("")
    lines.append("Reconciliation: pool bytes sum to {:,} = text {:,} − matched {:,} → `{}`; every census function classified exactly once → `{}`.".format(
        census["reconciliation"]["sum_of_pool_bytes"], t["text_bytes"], t["matched_bytes"],
        census["reconciliation"]["pools_sum_equals_census"], census["reconciliation"]["every_function_classified_once"]))
    lines.append("")
    lines.append("## Answer 2 — parked wall recipes, bytes per recipe (physics-priority ranking)")
    lines.append("")
    parked = census["pools"]["parked_recipe"]
    if not parked["available"]:
        lines.append("`parked_recipe` is an instruction pool: **null in this offline census** (needs code.bin + capstone; `synth.check_negative` labels each function with its negative-recipe id).")
        lines.append("")
        lines.append("On the box with code.bin: `uv run python tools/census.py --json` → `pools.parked_recipe.detail.recipes_by_bytes` is the definitive ranking (fam_sti 3rd pool word, if-conversion, bool-materialization, stack-arg, and the other neg-* recipes).")
    else:
        rec = (parked["detail"] or {}).get("recipes_by_bytes", {})
        lines.append("| Recipe | Functions | Bytes | % of census |")
        lines.append("|---|---:|---:|---:|")
        for rid, d in rec.items():
            lines.append("| `{}` | {:,} | {:,} | {} |".format(
                rid, d["functions"], d["bytes"], _fmt_pct(round(100.0 * d["bytes"] / t["census_bytes"], 4))))
        lines.append("")
        lines.append("Total parked: {:,} functions, {:,} bytes.".format(parked["functions"], parked["bytes"]))
    lines.append("")
    lines.append("### Shape-family residue subtotals (PASS shapes of `shared/shape_verification.json`)")
    lines.append("")
    shape = census["pools"]["shape_family_residue"]
    if not shape["available"]:
        lines.append("`shape_family_residue` is an instruction pool: **null in this offline census** (shapemine motif intersection over code.bin). Full-mode ranking: `pools.shape_family_residue.detail.families_by_bytes` (Id64, Pair, Delegate, Flag16/32, StateMgr/StateMgrPlain, SafeString/SafeStringBase, PtrList, Factory, Control2317, ...).")
    else:
        fam = (shape["detail"] or {}).get("families_by_bytes", {})
        lines.append("| Shape family | Functions | Bytes |")
        lines.append("|---|---:|---:|")
        for f, d in fam.items():
            lines.append("| {} | {:,} | {:,} |".format(f, d["functions"], d["bytes"]))
        lines.append("")
        lines.append("Total shape-family residue: {:,} functions, {:,} bytes.".format(shape["functions"], shape["bytes"]))
    lines.append("")
    lines.append("## Answer 3 — svc/CTRSDK region and the exclusion recomputation")
    lines.append("")
    svc = census["pools"]["svc_region"]
    ex = census["exclusion"]
    if not svc["available"]:
        lines.append("`svc_region` is an instruction pool: **null in this offline census** (capstone pass over code.bin; per-function svc numbers name the OS call via the public 3DS svc tables).")
    else:
        lines.append("svc/CTRSDK region: **{:,} functions, {:,} bytes** ({}% of .text).".format(
            svc["functions"], svc["bytes"], _fmt_pct(svc["share_of_text_pct"])))
        nums = (svc["detail"] or {}).get("svc_numbers", {})
        if nums:
            lines.append("")
            lines.append("| svc # | Functions | Bytes |")
            lines.append("|---|---:|---:|")
            for n, d in nums.items():
                lines.append("| {} | {:,} | {:,} |".format(n, d["functions"], d["bytes"]))
    lines.append("")
    lines.append("Honest-bytes share, shown both ways (sibling-project convention excludes prebuilt SDK/library regions from the target):")
    lines.append("")
    a = ex["share_vs_full_text"]
    b = ex["share_vs_target_minus_excluded_library"]
    c = ex["share_vs_target_minus_svc_and_library"]
    lines.append("- against full .text: {:,} / {:,} = **{}**".format(a["honest_bytes"], a["target_bytes"], _fmt_pct(a["share_pct"])))
    lines.append("- against target minus excluded_library ({:,} B): {:,} / {:,} = **{}**".format(
        ex["excluded_library_bytes"], b["honest_bytes"], b["target_bytes"], _fmt_pct(b["share_pct"])))
    if c is None:
        lines.append("- against target minus (svc_region + excluded_library): **null offline** — computed in full mode as honest {:,} / ({:,} − svc − {:,}) .".format(
            a["honest_bytes"], t["text_bytes"], ex["excluded_library_bytes"]))
    else:
        lines.append("- against target minus (svc_region + excluded_library) ({:,} + {:,} B): {:,} / {:,} = **{}**".format(
            ex["svc_region_bytes"] or 0, ex["excluded_library_bytes"], c["honest_bytes"], c["target_bytes"], _fmt_pct(c["share_pct"])))
    lines.append("")
    lines.append("## Gap arithmetic — the 50% goal")
    lines.append("")
    lines.append("- honest now: **{:,} B** = {} of {:,} B .text".format(g["honest_bytes_now"], _fmt_pct(g["honest_share_of_text_pct"]), t["text_bytes"]))
    lines.append("- 50% goal: {:,} honest bytes → needs **+{:,} honest bytes**".format(g["goal_honest_bytes"], g["needed_honest_bytes"]))
    lines.append("- winnable pools (all except excluded_library / svc_region): {:,} B across {} pools".format(
        g["winnable_bytes"], len(g["winnable_pools"])))
    lines.append("- smallest closing set (pools by bytes desc until the gap is covered): `{}` = {:,} B".format(
        ", ".join(g["closing_set_by_bytes_desc"]), g["closing_set_bytes"]))
    lines.append("- read: {}".format(g["note"]))
    lines.append("")
    im = census["instruction_metadata"]
    lines.append("## Instruction metadata (lifter curriculum input)")
    lines.append("")
    if im is None:
        lines.append("Null offline (needs the capstone pass). Full mode records per-function has_svc / has_vfp (vpush/vpop/vldr/vstr class) / has_ldrex_strex / has_ldm_stm plus per-function svc numbers in the `functions` entries.")
    else:
        for f in ("has_svc", "has_vfp", "has_ldrex_strex", "has_ldm_stm"):
            d = im[f]
            lines.append("- `{}`: {:,} functions, {:,} bytes".format(f, d["functions"], d["bytes"]))
    lines.append("")
    lines.append("## Per-function classification")
    lines.append("")
    lines.append("Machine-readable per-function rows (pool id, size, evidence) are in `shared/census.json` → `functions`. `python tools/census.py functions [--pool P] --json` prints them.")
    lines.append("")
    return "\n".join(lines)


def render_doc_file(census):
    return DOC_BEGIN + "\n" + render_doc(census) + "\n" + DOC_END + "\n"


def canonical_json(census):
    """Exactly what write_json(..., canonical=True) writes for the census."""
    text = json.dumps(census, indent=1, sort_keys=True)
    return "\n".join(line.lstrip() for line in text.splitlines())


def update_doc(census, write=False):
    with open(CENSUS_MD, encoding="utf-8") as stream:
        original = stream.read()
    pattern = re.compile(re.escape(DOC_BEGIN) + r".*?" + re.escape(DOC_END), re.DOTALL)
    if len(pattern.findall(original)) != 1:
        raise ValueError("docs/census.md needs exactly one generated block")
    updated = pattern.sub(lambda m: render_doc_file(census).rstrip("\n"), original)
    if write:
        atomic_write(CENSUS_MD, updated)
    return updated == original


# --------------------------------------------------------------------- cli

def _summary_text(census):
    t, g = census["totals"], census["gap"]
    out = []
    out.append("census mode: %s" % census["mode"])
    out.append(".text {:,} B, {:,} functions; matched {:,} B (honest {:,} B, hack {:,} B)".format(
        t["text_bytes"], t["functions"], t["matched_bytes"], t["honest_bytes"], t["hack_bytes"]))
    out.append("census input: {:,} functions, {:,} B".format(t["census_functions"], t["census_bytes"]))
    out.append("pool             functions      bytes  %of.text  available")
    for p in POOLS:
        pool = census["pools"][p]
        if pool["available"]:
            out.append("%-16s %8d %10d  %7.2f%%  yes" % (p, pool["functions"], pool["bytes"], pool["share_of_text_pct"]))
        else:
            out.append("%-16s %8s %10s  %7s  null (instruction pool)" % (p, "-", "-", "-"))
    out.append("gap to 50%%: +%d honest bytes (honest now %d = %.2f%%; goal %d)" % (
        g["needed_honest_bytes"], g["honest_bytes_now"], g["honest_share_of_text_pct"], g["goal_honest_bytes"]))
    out.append("exclusion both ways: vs full text %.2f%% | vs target-excluded_library %.2f%%%s" % (
        census["exclusion"]["share_vs_full_text"]["share_pct"],
        census["exclusion"]["share_vs_target_minus_excluded_library"]["share_pct"],
        "" if census["exclusion"]["share_vs_target_minus_svc_and_library"] is None else
        " | vs target-svc-library %.2f%%" % census["exclusion"]["share_vs_target_minus_svc_and_library"]["share_pct"]))
    rec = census["reconciliation"]
    out.append("reconciliation: pools sum %d == text-matched %d -> %s" % (
        rec["sum_of_pool_bytes"], rec["text_minus_matched_bytes"], rec["pools_sum_equals_census"]))
    return "\n".join(out)


def cmd_check():
    canonical = build_canonical()
    ok_json = ok_doc = None
    if os.path.exists(CENSUS_JSON):
        with open(CENSUS_JSON, encoding="utf-8") as stream:
            ok_json = stream.read() == canonical_json(canonical)
    else:
        ok_json = False
    if os.path.exists(CENSUS_MD):
        ok_doc = update_doc(canonical, write=False)
    else:
        ok_doc = False
    fresh = ok_json and ok_doc
    print("shared/census.json: %s" % ("current" if ok_json else "STALE"))
    print("docs/census.md:     %s" % ("current" if ok_doc else "STALE"))
    print("RESULT: %s (rerun `python tools/census.py --write` to refresh)" % ("FRESH" if fresh else "STALE"))
    return 0 if fresh else 1


def build_canonical():
    """The canonical committed census: ledger-pinned offline mode, always
    reproducible from committed inputs (CI has no code.bin)."""
    functions = read_json(os.path.join(ROOT, "functions.json"))
    starts = read_json(os.path.join(ROOT, "funcs.json"))["starts"]
    symbols = load_symbols()
    input_hashes = {
        "functions.json": sha256_file(os.path.join(ROOT, "functions.json")),
        "funcs.json": sha256_file(os.path.join(ROOT, "funcs.json")),
        "shared/symbols.jsonl": sha256_file(SYMBOLS) if os.path.exists(SYMBOLS) else None,
        "shared/recipes.json": sha256_file(os.path.join(ROOT, "shared", "recipes.json")),
        "shared/shape_verification.json": sha256_file(SHAPES_JSON),
    }
    sizes = function_sizes(starts)
    census_items = [(a, sizes[a], functions.get("%08X" % a) or {},
                     (functions.get("%08X" % a) or {}).get("status", "unmatched"))
                    for a in starts
                    if (functions.get("%08X" % a) or {}).get("status", "unmatched") not in MATCHED]
    hot = hot_size_map(census_items)
    audit_match = audit.stats(functions)["bytes_by_status"] == _census_bytes_by_status(functions, starts)
    return build_census(functions, starts, symbols=symbols, instr=None, fam_of=None,
                        hot=hot, mode="offline", input_hashes=input_hashes,
                        code_bin_sha1=None, audit_match=audit_match)


def cmd_write(write_full=False, image_path=None):
    if write_full:
        census = load_repo_inputs(image_path)
        if census["mode"] != "full":
            sys.stderr.write(SETUP_HINT + "\n")
            return 2
        os.makedirs(FULL_DIR, exist_ok=True)
        write_json(os.path.join(FULL_DIR, "census-full.json"), census, canonical=True)
        atomic_write(os.path.join(FULL_DIR, "census-full.md"), render_doc_file(census))
        print("wrote %s and %s" % (os.path.join(FULL_DIR, "census-full.json"),
                                   os.path.join(FULL_DIR, "census-full.md")))
        return 0
    canonical = build_canonical()
    write_json(CENSUS_JSON, canonical, canonical=True)
    update_doc(canonical, write=True)
    print("wrote %s and %s (mode=offline, ledger-pinned)" % (CENSUS_JSON, CENSUS_MD))
    if os.path.exists(CODE_BIN) and Cs is not None:
        print("note: code.bin+capstone present — `python tools/census.py --json` / `--write-full` carry the instruction pools (svc_region, parked_recipe, shape_family_residue)")
    else:
        sys.stderr.write(SETUP_HINT + "\n")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", nargs="?", choices=("pools", "functions", "check"), default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--pool", default=None)
    ap.add_argument("--write", action="store_true", help="write canonical shared/census.json + docs/census.md")
    ap.add_argument("--write-full", action="store_true", help="write full-mode census under logs/census/ (needs code.bin+capstone)")
    ap.add_argument("--image", default=None, help="raw code image override (testing); default: SHA-1-verified code.bin")
    args = ap.parse_args()

    if args.write and args.write_full:
        ap.error("--write and --write-full are exclusive")
    if args.write:
        return cmd_write(write_full=False)
    if args.write_full:
        return cmd_write(write_full=True, image_path=args.image)
    if args.cmd == "check":
        return cmd_check()

    census = load_repo_inputs(args.image)
    degraded = census["mode"] != "full"
    if args.cmd == "pools":
        payload = {"mode": census["mode"], "pools": census["pools"], "gap": census["gap"],
                   "exclusion": census["exclusion"]}
        if args.json:
            print(json.dumps(payload, indent=1, sort_keys=True))
        else:
            print(_summary_text(census))
    elif args.cmd == "functions":
        rows = [dict(addr=a, **census["functions"][a]) for a in sorted(census["functions"])]
        if args.pool:
            rows = [r for r in rows if r["pool"] == args.pool]
        if args.json:
            print(json.dumps(rows, indent=1, sort_keys=True))
        else:
            for r in rows:
                print("%s %6dB %-22s %s" % (r["addr"], r["size"], r["pool"], json.dumps(r["evidence"], sort_keys=True)))
    else:
        if args.json:
            print(json.dumps(census, indent=1, sort_keys=True))
        else:
            print(_summary_text(census))
    if degraded:
        sys.stderr.write(SETUP_HINT + "\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
