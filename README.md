# The Legend of Zelda: A Link Between Worlds (3DS, USA): matching decompilation (work in progress)

This repository holds C/C++ source for individual functions of *A Link Between Worlds*. Each source compiles with
the original compiler with the goal of producing **exactly the same bytes** as the function in the game. It is an unfinished project, shared
so that anyone who wants to can continue it.

**No game binary, data files or assets are included.** You need your own copy of the game's code binary. The compiler is
not included either.

## Status

<!-- generated:status -->
| | Functions | Share of 25,986 | .text bytes | Share of 5,841,180 B |
|---|---:|---:|---:|---:|
| Matched, source included | 16,873 | 64.9% | 1,428,564 | 24.5% |
| of which honest (no hack) | 16,090 | 61.9% | 1,303,428 | 22.3% |
| of which hack | 783 | 3.0% | 125,136 | 2.1% |
| Earlier match, source not included | 114 | 0.4% | 15,396 | 0.3% |
| Not matched yet | 8,986 | 34.6% | 4,392,632 | 75.2% |
| Lifted (semantic, not byte-exact) | 0 | 0.0% | 0 | 0.0% |
| Excluded library | 13 | 0.1% | 4,588 | 0.1% |

Remaining for an honest decompilation (excluding libraries): **9,883** functions.

Sizes use consecutive starts in `funcs.json` within `.text` (`0x100000`–`0x69211C`), not the whole binary.
3 interior-address entries are not counted as separate functions.

Hack reasons (a function can have several): weak 527, __schedule_barrier 156, asm 94, identical_arms 22, perm_t 15, dummy_local 12, volatile_dummy 3.
<!-- /generated:status -->

**Correction to the first publication.** 419 entries of the first publication (2026-10-15) were removed after a
relocation audit. The old checker masked relocated words and could print `RESULT: MATCH` for the wrong call or global.
The checker now validates supported relocation identities and rejects unknown symbols, unsupported relocations,
and unproved linker rewrites. Every published `honest` entry is reverified end-to-end by the image gate:
`python tools/rebuild_check.py` recompiles all of them and reports `RESULT: EXACT MATCH` (SHA-1 equal to the
target image). 211 pre-hardening entries that failed that gate were de-registered to unmatched (wrong-callee
labels / pool-layout drift); they can be re-matched properly later.

Counts are generated offline from `functions.json` and `funcs.json`:
`python3 tools/audit.py readme --write`. CI rejects stale generated summaries.

**What "honest" means here.** The source compiles to the exact bytes **without** any of these tricks:
- `__attribute__((weak))` / `__weak` used only to stop a tail call;
- `__schedule_barrier()`;
- inline `asm`;
- dummy or `volatile` locals that are never really used;
- out-of-bounds dummy arrays;
- `& 0xffffffff` no-op masks;
- if/else blocks whose two arms are identical;
- permuter-only `perm_t` types.

`functions.json` records `honest`/`hack` for sources and lists hack reasons. The automatic scan catches obvious
textual constructs, not every semantic trick; passing it is not proof of honesty.

## Layout

| Path | Contents |
|---|---|
| `functions.json` | The index: `address -> {path, cc, flags, status, hack_reasons}` |
| `src/` | The sources. Paths keep the layout of the original workspace (many agents and tools wrote to many folders), and local `#include`s are relative to each file |
| `src_lifted/` | Lifted semantic scaffolds (`func_<ADDR>.c`, LIFTED banner) — never registrable as matched |
| `shared/include/` | Project headers (written for this project) |
| `shared/symbols.jsonl` | Names inferred for some functions |
| `shared/extra_starts.txt`, `shared/not_starts.txt` | Corrections to the function table |
| `funcs.json` | The function table: start addresses, call targets, pointers. Addresses only, no code |
| `tools/fn.py` | Disassembly, cross-references, and the byte-exact checker |
| `tools/audit.py` | Offline invariant audit of `functions.json` + status-table stats |
| `tools/lift.py` | ARM32 semantic lifter for unmatched functions (`src_lifted/`, status `lifted`) |
| `tools/hybrid_build.py` | Hybrid image builder (`build/hybrid.bin`: matched + lifted + original bytes) |
| `tools/objdiff.py`, `tools/setup_objdiff.py` | objdiff-cli wrapper (object-level diffs) + its one-time pinned-binary setup |
| `tools/sdkmap.py` | SDK fingerprinting pipeline (nnsdk inventory, offline `plan`, phone-gated `fingerprint`/`try-compile`) |
| `shared/nnsdk_inventory.json` | Generated metadata inventory of `3dsdecomp/nnsdk` @ `d50a4b8` (names, mangled patterns, paths, hashes — no SDK source) |

## Requirements

1. **Python 3.10+**. Install analysis dependencies with `uv sync` (creates `.venv`; then run tools as
   `.venv/bin/python tools/…` or via `uv run python tools/…`), or with `python3 -m pip install capstone`.
   Offline tests, audit, and worklist `status`/`report` require only the standard library.
2. **The game code binary.** Save it as `code.bin` in the repository root. It is the decompressed `.code` section of
   the USA release, dumped from your own copy, 6,455,296 bytes, SHA-1 `e6ab7d66ee62e879248b0660aaf38d22202e604b`.
3. **ARM Compiler (armcc) 4.1, build 1049.** Place it at `tools/armcc/4.1/b1049/bin/armcc.exe`. Every published
   function uses this build unless its index entry specifies otherwise. You need your own licensed copy.
   On Linux/macOS, the Windows executable also requires Wine (available as `wine` on `PATH`).

The lifting/hybrid/oracle tools (`tools/lift.py`, `tools/hybrid_build.py`, `worklist.py verify`) use the same
inputs: `lift`/`batch` and the full hybrid build need `code.bin` (+ armcc under Wine), and `verify` additionally
needs the Zakuro replay corpus in `logs/coverage/` and a 3dsrecomp build (see `docs/RECOMP_IDEAS.md`). Without
them every one of these commands degrades to an offline plan or a printed list of the exact commands to run
later on the phone — nothing is faked or skipped silently.

Default flags:
```
--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections
```
Some functions also need `--apcs=/fpic`, and a few use `--fpu` variants. `functions.json` has the exact `cc` and `flags`
of each function.

## Usage

```
python3 tools/fn.py show  0x001747E8                     # annotated disassembly of the original function
python3 tools/fn.py check <path from functions.json> 0x<ADDR> --cc <cc> --flags "<flags>"
```
`check` compiles the file, finds the function, compares it with the game bytes, and prints `RESULT: MATCH` or an
aligned diff. Some C++ members need `--sym <mangled-name substring>`.
All compiler jobs are serialized with a repository lock; sweep/permuter accept only `--jobs 1`.
Use the exact `cc` and `flags` in the index. Binary size and SHA-1 are checked before analysis.
Unknown relocation identities are a non-match, even if instruction placeholders are equal.

Offline validation (no game dump, compiler, Wine, or Capstone required):
```
python3 -m unittest discover -s tests -v
python3 tools/audit.py
python3 tools/audit.py readme
```
Refiner checkpoints retain immutable checked variants and a wave cursor. Winner copies keep their `.c`/`.cpp`/`.cc`
extension. Legacy checkpoints predate strict relocation checking and require an explicit `--fresh` restart.

The refiner also has an opt-in **repair proposal pass** (roadmap H3), inspired by
[RetroReversing/decomp-repair](https://github.com/RetroReversing/decomp-repair) (AGPL-3.0-only; ideas ported, none of
its source committed — see `docs/AUTOMATION_PLAN.md` phase 9). `python3 tools/refine.py 0xADDR --proposals repair
--repair-budget 12` checks single-change variants of the current near-miss (literal nudges from the diff words,
branch-arm swaps, bool casts, register hints, local lifetimes, operand order, explicit casts, volatile placement)
after the dna-twin waves and before the synth fallback; `python3 tools/refine.py propose [--json]` lists the same
variants offline over the logged near-misses. The pass proposes, never judges: only `fn.py check` decides a variant
and only `worklist.py register` records a `RESULT: MATCH`. Without `--proposals` the refiner's behavior is
unchanged.

## Lifted scaffolds and hybrid builds

`tools/lift.py` translates unmatched functions into **semantic C scaffolds** under `src_lifted/`
(Hookshot-style ARM32 lifting with capstone). Lifted code is never byte-exact and is never registered
as `matched`/`honest`/`hack`: `functions.json` records it with status `lifted`, the status table above
counts it in its own "Lifted (semantic, not byte-exact)" row (excluded from all matched/honest
arithmetic), `worklist.py register` refuses `src_lifted/` sources, and `fn.py check` on a lifted file
is informational only. Its purpose is oracle coverage, hybrid builds, and a starting scaffold for later
matching work.

```
python3 tools/lift.py targets --json                 # offline list of liftable addresses (unmatched / source_lost / no-twin)
python3 tools/lift.py lift 0x005AB1D0                # lift one function (needs code.bin) -> src_lifted/func_005AB1D0.c
python3 tools/lift.py batch --limit 200 --budget 20  # budgeted, resumable queue (state: logs/lift/)
python3 tools/lift.py status / report --json
python3 tools/hybrid_build.py check                  # offline composition plan of the hybrid image (no armcc needed)
python3 tools/hybrid_build.py --out build/hybrid.bin # full build: matched recompiled + lifted stubs + original bytes
python3 tools/worklist.py verify 0x005AB1D0 --count 500  # behavioral oracle (3dsrecomp/Zakuro replay corpus)
```

The hybrid image assembles three layers at the original addresses — byte-exact matched sources
recompiled with armcc, lifted stubs, and the original `code.bin` bytes for everything else — into
`build/hybrid.bin`. It is a **testing artifact for the behavioral oracle, not a release artifact**;
`tools/rebuild_check.py` remains the only byte-exact gate and its semantics are unchanged. All compiler
jobs stay serialized under the repository lock (`--jobs 1`). `worklist.py verify` records an
oracle-verified candidate as `semantic_match` with a `wall_class` (byte diffs remain, behavior equal on
the replay corpus); it never counts toward honest bytes. The parked walls 005AB1D0, 0059F7B8, 005A8AA0,
005CBE9C are the first eligible `verify` candidates. See `docs/AUTOMATION_PLAN.md` phase 7.

## Object-level diffing (objdiff-cli)

`tools/objdiff.py` is a thin, stdlib-only wrapper around
[objdiff-cli](https://github.com/encounter/objdiff) (object-level, data-aware
diffing with ARM support), so multi-function objects and literal-pool data stop
being triaged by eye. Where it helps: **multi-function objects** (per-unit
`match_percent` instead of one whole-file verdict), **pool data** (section
`data_diff` blocks), **gate-failure triage** (`rebuild_check.py` mismatches at
object granularity), and **hybrid layer verification** (matched vs lifted
objects side by side). `triage.py` behavior is unchanged.

The binary is never committed and never downloaded at build time. One manual
setup downloads the **pinned** release (objdiff-cli v3.8.3) into the gitignored
`tools/bin/`, verifying the asset's SHA-256 before use:

```
python3 tools/setup_objdiff.py                          # this host (auto-detected)
python3 tools/setup_objdiff.py --target linux-aarch64   # the phone (Termux)
python3 tools/setup_objdiff.py --check                  # verify an installed binary
```

```
python3 tools/objdiff.py units <object> --json                 # unit/section list of one object
python3 tools/objdiff.py diff <base-obj> <target-obj> --json   # machine-readable object diff
python3 tools/objdiff.py diff base.o target.o --symbol func_005AB1D0   # one unit
```

`--json` re-emits objdiff-cli's own JSON (with a structured passthrough if the
output ever resists parsing). Without the binary or the object files, every
command prints the exact setup command above and exits 2 — the same
degradation convention as `tools/lift.py`. The real ARM objects come from the
phone-side armcc runs; the committed tests mock the subprocess.
## SDK fingerprinting (sdkmap)

`tools/sdkmap.py` (roadmap H1) fingerprints the unmatched tail against the public nnsdk reconstruction
([3dsdecomp/nnsdk](https://github.com/3dsdecomp/nnsdk), pinned at `d50a4b89d13c929d2438abf92e5a48f039efffbf`;
that revision ships no LICENSE file), so SDK functions embedded in the game can be matched by compiling
the SDK's own source with armcc instead of reverse engineering them. The nnsdk clone stays in an
**untracked** directory (outside the repo or under the gitignored `logs/`); the only committed artifact is
the generated metadata inventory `shared/nnsdk_inventory.json` — names, mangled-name patterns, namespaces,
source paths, per-file hashes. No SDK source and no game-derived raw data is committed.

```
python3 tools/sdkmap.py plan --limit 50 --json     # offline ranked SDK candidates (state: logs/sdkmap/plan.json)
python3 tools/sdkmap.py status / report --json    # offline views over logs/sdkmap/
# phone only (needs code.bin + armcc under Wine + the nnsdk clone):
uv run python tools/sdkmap.py fingerprint --budget 20
uv run python tools/sdkmap.py try-compile 0x<ADDR> --nnsdk-dir <nnsdk-clone> --run
```

Without `code.bin`/armcc, `fingerprint` and `try-compile` exit 2 and print the exact phone commands.
A successful SDK match registers through the standard `worklist.py register` flow with a
`sdk:nnsdk <path>@<rev>` note on the entry. See `docs/AUTOMATION_PLAN.md` phase 8.

## How it was made

Most of the sources were written by **automated tools**:
- many LLM agents, each working on one function;
- a custom translator that lifts machine code to compiler-shaped C;
- source permuters;
- "twin" harvesting, which reuses a matched source for byte-identical or same-shape functions.

**Sources were historically accepted by `tools/fn.py check`; that is not a claim of revalidation under the hardened checker.** Some communities do not accept
machine-written decompilation, so please keep this in mind if you merge anything.

See `docs/LESSONS.md` for what worked, what did not, and the measured numbers.

## Where to go next

The unmatched functions in the generated table are the hard tail. Our tests show the main blocker is **the shape of small inline
helpers and classes from the game's own headers**:
- inlined constructors;
- setters with parameters;
- temporary string objects;
- conversion operators.

The bytes show *that* a helper was inlined at a site, but not its exact source form. A shared, correct header library
of these helpers would unlock many functions at once. This is how other large decompilation projects grew.

## Contributors

- **matthis** ([mmaupas/albw-decomp-ai](https://github.com/mmaupas/albw-decomp-ai)) added the automation tools in
  `tools/` (worklist, refine, synth, dna, sweep, permuter, triage, twins, dehack, recipes, audit and others), the
  shared headers `shared/include/albw_types.h` and `albw_common.h`, `shared/recipes.json`, `AGENTS.md` and the agent
  skills, new matches (twin harvesting, de-hacked sources, functions that had lost their source), and many entries in
  `docs/LESSONS.md`. The index records historical acceptance; current verification limitations are described above.

## Legal

This project contains no Nintendo binaries, data files or assets, and no compiler files.
- As in other decompilation projects, the sources contain the string literals the functions reference.
- It contains no material from non-public SDKs. It was scanned for official SDK file headers and similar markers, and
  prebuilt middleware/SDK library functions were excluded.

You must supply your own legally obtained game dump and compiler. The repository has no license file yet; the owner
decides.

---

### ملخص بالعربي
- **وش هذا المشروع:** مشروع تفكيك مطابق للعبة Zelda: A Link Between Worlds على 3DS، بهدف إنتاج نفس بايتات الدوال باستخدام مترجم armcc 4.1.
<!-- generated:arabic-status -->
- **وين وصلنا:** 16,873 دالة لها مصدر (64.9%)، منها 16,090 نظيفة (61.9%) و783 بحيل.
- **وش باقي:** 8,986 دالة غير مطابقة؛ الباقي لتفكيك نظيف، باستثناء المكتبات، 9,883 دالة.
<!-- /generated:arabic-status -->
- الأرقام من الفهرس؛ لم تُعَد مراجعة كل المصادر بالمُدقّق الجديد الأكثر صرامة.
- **وش ما يشمل:** ما فيه أي ملفات من اللعبة (ملف الكود أو ملفات البيانات) ولا المترجم. كل واحد يجيب نسخته بنفسه.
- **ليش منشور:** الشغل منشور عشان أي أحد يبي يكمّل.
