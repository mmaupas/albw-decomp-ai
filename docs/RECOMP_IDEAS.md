# Ideas imported from logs/decomp-tools-review.md (N64Recomp / ReXGlue research)

`logs/decomp-tools-review.md` is a deep-research report on static
recompilation toolchains (N64Recomp, ReXGlue) and the 3DS recomp scene
(3dsrecomp/Zakuro, TriAevum, MH4U-in-Azahar). This project is a *matching*
decompilation with a byte-exact oracle (`tools/fn.py check`), so the
porting machinery does not apply directly — but three of the report's
techniques improve discovery, prioritization, and validation. Status of each
is below; tools live in `tools/`.

## 1. Binary-derived symbol cross-check — IMPLEMENTED: `tools/symscan.py`

ReXGlue derives function boundaries from `.pdata` exception tables; the ARM
analogue is `.ARM.exidx`/`.ARM.extab`, which lives at the tail of .data
(`0x6FD000`–`0x6FF000` in this binary).

- `python tools/symscan.py scan` — parses all 615 exidx entries and
  cross-checks the derived function starts against `funcs.json`.
  **Validated result: 615/615 already present, 0 missing** — our function
  table is consistent with the unwind metadata. Exit code 1 if any derived
  start is missing, so it can gate future table edits.
- `python tools/symscan.py vtables` — ReXGlue VTableScanner analogue: runs
  of >= 3 aligned text pointers in rodata/data are C++ vtables. 2185 runs
  in rodata (30950 entries, 30844 already starts; the 106 non-starts are
  data that happens to look like code pointers, e.g. `0x00640000`), 11 in
  data. Useful to spot vtable entries that point at interior addresses.
- `python tools/symscan.py helpers` — armcc/armlib signature anchors,
  generalizing the LESSONS.md "armlib memfunc cluster" disposal: detects
  `__aeabi_memclr4` (`mov lr,r2` + conditional `stm r0!,{r2,r3,ip,lr}` fill
  — a compiler never clobbers lr mid-body), `__aeabi_memclr`, and the
  unique `push {r0,lr}` memset wrapper. **Validated: all three anchors
  detected; `push {r0,lr}` occurs exactly 3 times in the whole binary.**

## 2. Coverage-weighted backlog ranking — IMPLEMENTED: `tools/coverage_rank.py`

3dsrecomp "learns from the emulator": instrument Zakuro/Azahar to log
executed addresses, then decompile hot paths first.

- `python tools/coverage_rank.py rank [--coverage logs/coverage/executed.jsonl] [--top N] [--json]`
  joins a coverage log (JSONL: `{"addr": "005CBE9C+0x10", "hits": 1400000}`)
  with `worklist.py report --json` and re-ranks by
  `score = frac * (1 + log10(1 + hits))`. Without a coverage file the order
  is exactly the report order (validated). With the synthetic test log,
  005CBE9C (frac 0.53, 1.4M hits) correctly jumps from rank 4 to rank 1.
- `python tools/coverage_rank.py explain <addr>` shows one row's inputs.

Producing a real log — **DONE in this Termux environment** (2026-11-07):
Zakuro (github.com/fearkov/zakuro) is pure Rust and its `zakuro-core`
crate builds fine on aarch64-android with the system rust 1.99.1. The GUI
frontend doesn't (winit pulls android-activity, which needs the NDK), but
a 60-line `covtool` binary linking `zakuro-core` runs the interpreter
headless and counts every PC exactly:

    python tools/coverage_run.py --rom <decrypted USA .3ds> --frames 600
    python tools/coverage_rank.py rank --top 20

Measured on the USA ALBW dump (sha1-verified against the project's
code.bin): 600 frames (~10 s of game time, title screen) = 242,950 distinct
PCs / ~530 M instructions, 5,368 functions covered. Top of the re-ranked
backlog: 00115234 (frac 0.50, 5,300 hits, twin of matched 00115224) is now
#1 — a much better target than the cold 85% walls. 0010FC34 is the
hottest function in the game (7.6 M hits) but only 8% matched.
The ROM itself was already decrypted (ExeFS plaintext — verified byte-
identical to code.bin), so Zakuro loads it directly. covtool itself is
scratch (~/zakuro-work/covtool), not committed; the wrapper
`tools/coverage_run.py` is.

Alternative sources if Zakuro ever stops fitting: fork Azahar/Citra and
increment a counter keyed on PC in the ARM11 core, or use a Luma3DS-style
hook on real hardware.

## 3. Behavioral oracle (per-function replacement in a running game) — NOW FEASIBLE VIA ZAKURO

The report's highest-value idea for a matching decomp: swap one decompiled
function into an otherwise-original running game (weak-alias / linker
priority / single-file recomp mode in N64Recomp; `__imp__` overrides in
ReXGlue; MH4U runs recompiled ARM11 code inside Azahar's core) and compare
behavior. This would let us distinguish "bytes differ but semantics equal"
from a real mismatch — potentially reclassifying near-misses stuck at
83–85% on armcc scheduling walls (005AB1D0, 0059F7B8, 005A8AA0, 005CBE9C).

**Update 2026-11-07: the blocker is gone.** Zakuro runs in this Termux
environment (see section 2), and 3dsrecomp has first-class support for
exactly this: `3dsrecomp build <rom> --overrides dir/` compiles hand-written
C (`RECOMP_OVERRIDE(0x005AB1D0) { ... }`) that runs *instead of* the
generated code at that address, with `RECOMP_ORIGINAL(0x005AB1D0)` to call
the original, and `3dsrecomp verify` checks every recompiled function
against Zakuro's interpreter from the same state, comparing registers,
flags and memory. Concrete plan: take a near-miss source, express it as a
`RECOMP_OVERRIDE` against the running game, and diff a deterministic
replay (ZAKURO_RECORD / ZAKURO_REPLAY env vars exist for scripted inputs)
against the unpatched run. Not yet wired into the worklist — the natural
next step after coverage-driven re-ranking.

## 4. Legal posture — already enforced

The report's "ship no game code, require the user's own dump" rule matches
this repo's conventions: `code.bin`, `*.bin`, and `tools/armcc/` are
gitignored; only string literals referenced by functions are committed.
Verified with `git check-ignore` and `tools/audit.py` (see git log).
