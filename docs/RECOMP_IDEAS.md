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

Producing a real log (not possible in this Termux environment — no 3DS
emulator can execute here): fork Azahar/Citra and increment a counter keyed
on PC in the ARM11 core, dump JSONL on exit; or log PCs in Zakuro's
interpreter loop; or use a Luma3DS-style hook on real hardware.

## 3. Behavioral oracle (per-function replacement in a running game) — DOCUMENTED, BLOCKED HERE

The report's highest-value idea for a matching decomp: swap one decompiled
function into an otherwise-original running game (weak-alias / linker
priority / single-file recomp mode in N64Recomp; `__imp__` overrides in
ReXGlue; MH4U runs recompiled ARM11 code inside Azahar's core) and compare
behavior. This would let us distinguish "bytes differ but semantics equal"
from a real mismatch — potentially reclassifying near-misses stuck at
83–85% on armcc scheduling walls (005AB1D0, 0059F7B8, 005A8AA0, 005CBE9C).

**Blocker:** this environment (Termux/Android, no GPU, no 3DS emulator
available) cannot run the game, so no behavioral comparison is possible
here. When a host with Azahar/Zakuro is available, the concrete plan is:
load the USA dump, apply a single-function patch built from a registered
decomp source, and diff a deterministic playthrough (scripted inputs)
against the unpatched run. Until then, `fn.py check` remains the only
oracle, and the scheduling walls stand as documented in LESSONS.md.

## 4. Legal posture — already enforced

The report's "ship no game code, require the user's own dump" rule matches
this repo's conventions: `code.bin`, `*.bin`, and `tools/armcc/` are
gitignored; only string literals referenced by functions are committed.
Verified with `git check-ignore` and `tools/audit.py` (see git log).
