# Automation plan: agent-driven decompilation for small LLMs

Goal: reduce the per-function workflow to a few tool commands with
machine-readable output, so an agent with a *small* LLM can keep matching
functions without holding compiler-physics expertise in context. All expert
knowledge moves out of the agent's head and into tools + recipe data.

## Design contract (what makes it small-LLM-safe)

1. **One command = one decision.** Every tool prints a verdict and, when
   applicable, the suggested next command. The agent never improvises
   flag sets, construct classes, or mutation choices.
2. **Structured output.** Commands advertising `--json` emit one JSON value
   on stdout, with progress on stderr. Not all legacy commands implement it.
   The agent's job is to read a handful of fields, not disassembly.
3. **Budgets are built in, not chosen.** Probe budgets, job counts (`--jobs 1`
   on this device — see OOM note in LESSONS.md), and timeouts are defaults.
4. **Never trust, always verify.** Only `fn.py check`'s `RESULT: MATCH`
   registers a function. Every other stage is a *suggestion*.
5. **Idempotent and resumable.** Every stage writes state to disk; a crashed
   run (OOM, wine hang) must be restartable with no cleanup ceremony.

## Current state

| Piece | Status |
|---|---|
| `tools/triage.py` | done — candidate list, skip classes |
| `tools/sweep.py` | done — variant sweep + OP/REG/PERM classifier |
| `logs/pseudocode/` | done — 9,306 Ghidra dumps |
| `tools/dna.py` | done — index built (25,986), acceptance 20/20 + 7/7, `--json` everywhere |
| `tools/recipes.py` + `shared/recipes.json` | done — 13 entries (7 positive, 6 negative) |
| `tools/synth.py` | done — store-init class, DEFER otherwise; class coverage grows with use |
| `tools/shapemine.py` | done — n-gram motif clusters over all 25,986 starts; `next` prints the top unreported header-shape candidate |
| `tools/refine.py` (phase 4) | done — closed-loop refiner, acceptance 5/5 reproduced from skeleton-only restart |
| `tools/worklist.py` (phase 5) | done — next/register/report/status; first auto-registered match 003E60D4 |
| `tools/shape_verify.py` | done — >=3-site byte-exact admission protocol for header shapes |
| `tools/reharvest.py` (phase 5b) | done — after each admitted shape batch, re-run refine+register over the shape's unindexed family (shapemine motif overlap) |
| `tools/lift.py` (phase 7) | done — ARM32 semantic lifter -> `src_lifted/`, status `lifted`, never matched |
| `tools/hybrid_build.py` (phase 7) | done — hybrid image (matched+lifted+original) -> `build/hybrid.bin`, `--check` offline |
| `worklist.py verify` (phase 7) | done — RECOMP_OVERRIDE + behavioral_oracle + Zakuro corpus, status `semantic_match` + `wall_class` |
| `tools/proposals_repair.py` + `refine --proposals repair` (phase 9) | done — opt-in repair proposal pass, offline-tested (see phase 9) |
| `AGENTS.md` + skills | done — AGENTS.md is facts+invariants; the loop is `.agents/skills/decomp-loop`, expert work `.agents/skills/decomp-manual` |

## Phases

### Phase 1 — Finish DNA index (dna.py)

- Complete `python tools/dna.py index` over all 25,986 starts.
- `dna.py query 0xADDR` prints ranked structural twins with their registered
  source paths, and emits `NEXT:` line with the suggested action
  (`twin:<path>` / `synthesize` / `defer`).
- `dna.py offset 0xNN` for struct-field type discovery stays.
- **Acceptance test:** for 20 known-matched functions, the real source's
  function ranks in the top-5 of its own query. Tune weights until it does.
- Add `--json` to all subcommands.

### Phase 2 — Recipe corpus (shared/recipes.json)

Machine-checkable encoding of everything LESSONS.md taught:

```json
{
  "id": "strd-merge",
  "shape": "two adjacent u32 stores into [rX,#k] merged to STRD",
  "requires": ["both values already in registers", "no intervening address computation"],
  "source": "two consecutive stores; second value anchored via &self->member",
  "flags": ["default"],
  "refs": ["LESSONS.md#strd", "00102FB4"]
}
```

Two kinds of entries:
- **positive recipes** — target shape → winning source construct + flags
  (seed from all honest matches: STRD pair via nested struct + self-anchor,
  keep-producer r2-zero via live 2nd arg at -O2, VLDM batching via all-used
  float locals, `p += N` WB only when pointer reused, etc.);
- **negative recipes** (hard skips) — shapes that are unproducible from C
  (svc stubs, mrc/mcr TLS ops, veneers, s2-scratch f2uiz, 00115234-style r1!
  writeback, guarded 2-op VFP predication). The synthesizer/queue checks
  these BEFORE burning a compile.

A small tool `tools/recipes.py add|query <dna-shape>` keeps the corpus
queryable; LESSONS.md stays the human-readable mirror.

### Phase 3 — Skeleton synthesizer (tools/synth.py)

`python tools/synth.py 0xADDR` → writes `src/work8/synth/func_XXXX.c` (or
reports `UNPRODUCIBLE` if a negative recipe matches).

Source of truth, in order: disassembly store-map (byte-accurate) > call-list
+ pool refs > Ghidra pseudocode (semantic hints only — known to miss tricks
like dead-arg liveness). Synthesized classes, smallest-first:

1. **store-init** — `self->f = v;` lines from the store-map
   (`c0`→0, `aN`→`&self->member`, `l`→load, `x`→call result).
2. **getter/setter wrappers** — `mov r4,r0; bl helper; mov r0,r4` family.
3. **table lookups** — pool-ref + index scaling.
4. **tail thunks** — argument-preserving `b target`.
5. **arith/logic leaves** — mnemonic sequence → expression guess
   (byteswap, min/max, masks), refined by sweep.

Output includes the ready-to-run `sweep.py` spec, so phase 4 is one command.

### Phase 3b — Shape miner (tools/shapemine.py)

Systematic replacement for the hand-mined `shared/include/albw_shapes.h`
entries. `index` disassembles every start and hashes all 4/5-grams of the
normalized token stream (cond stripped, regs→r, imms→#, pool→POOL,
calls→CALL). `rank` clusters n-grams by posting list and scores
file_frequency(matched) × unindexed_overlap; `--focus stores` (the `next`
default) keeps only store-dense call-free motifs — the inlined ctor/setter
shapes that become header structs. `next` prints the best unreported
candidate with a `NEXT:` line; `candidate <id>` emits a paste-ready draft in
`logs/shapemine/candidates/<id>.h` with example sources and the unindexed
functions the shape would unlock. State is resumable under `logs/shapemine/`.

### Phase 4 — Closed-loop refiner (tools/refine.py)

`python tools/refine.py 0xADDR --budget 60` — wraps sweep.py with
diff-class-driven mutation, no hand-written specs:

- starts from a twin source (dna) or a synthesized skeleton (synth);
- loop until MATCH or budget exhausted:
  - `REG`-class best → mutate statement order / locals decl order / flags
    grid (-O2, -O3±Otime, per-function flag variants from functions.json
    neighbors) / known liveness tricks from recipes;
  - `PERM`-class best → full BODY permutation sweep;
  - `OP`-class best → swap construct class (store form, guard form, helper
    style) per recipes;
- each checked variant gets an immutable path; `state.json` atomically records
  the winner, complete wave and cursor. `best.c`/`best.cpp`/`best.cc` is a derived
  copy repaired from that path on resume. Every candidate appends to `history.jsonl`;
- budgets are cumulative checks; a budget-limited wave resumes at its next variant.
  Legacy checkpoints require `--fresh` because their verifier was less strict.

**Acceptance:** reproduce ≥5 known honest matches from skeleton-only
restart (drop the original source, regenerate, refine to MATCH).

### Phase 5 — Queue driver (tools/queue.py)

`python tools/worklist.py next` — the *only* command a small agent needs:

```
$ python tools/worklist.py next
CANDIDATE 0x0049F6DC (24B, list-splice, no negative recipe)
STATUS    synth: skeleton written src/work8/synth/func_0049F6DC.c
NEXT      python tools/refine.py 0x0049F6DC --budget 60
```

- pulls from triage list, skips negative-recipe shapes, runs dna → synth,
  hands the agent the next command;
- `queue.py register <addr> <src> <flags>` — re-runs fn.py check, refuses
  unless `RESULT: MATCH`, refuses existing source/index entries and detectable
  tricks, then atomically updates functions.json under a publication lock.
  Run `python3 tools/audit.py` before committing; this is an offline invariant
  check, not a fresh compiler verification of existing sources;
- `queue.py report` — near-miss table (addr, best %, diff class, one-line
  hypothesis) for human/large-LLM review;
- state in `logs/autodecomp/state.json`; crash-safe (`--jobs 1`,
  Popen+start_new_session+killpg, per-step timeouts — the OOM rules are
  encoded here, not remembered).

### Phase 5b — Re-harvest after every shape batch (tools/reharvest.py)

Each shape admitted to `shared/include/albw_shapes.h` (passing
`shape_verify.py`) changes what dna twins / synth predict: a twin whose
source uses the header shape now compiles correctly where it was the "wrong
construct". Twins unlock twins — the Nov 2-4 batches were this effect at
instruction level; this repeats it at header level.

`python tools/reharvest.py next` picks the next PASS shape and prints
`run <shape> --limit M --budget B`. `run` resolves the shape's unindexed
family (shapemine n-gram motifs shared by >= 2 verified sites, ranked by
overlap), refines each target from its dna twin, and registers matches via
`worklist.py register` (nothing registers without fn.py check MATCH).
`targets <shape>` lists the family without spending oracle budget.

### Phase 6 — AGENTS.md rewrite

Restructure so the expert workflow becomes a reference appendix and the
**default loop is the tool loop**:

- **"Standard loop (use this)":** `worklist.py next` → run the suggested
  command → on MATCH: `queue.py register` → `git commit` → repeat; on
  budget-exhaust: `queue.py report` entry, move on. ~15 lines.
- **"When to go manual":** functions the queue marks `defer` (large, weird
  register physics); then the current expert workflow applies, with LESSONS
  as required reading.
- **"Rules that never change" (kept verbatim):** honesty rules, RESULT:
  MATCH as the only truth, hack recording, legal boundaries (no binary,
  no SDK material), never extract code.bin from rom/.
- **Tool quick-reference table:** one line per tool with its exact command
  and what to read from its output.
- Explicit note: AGENTS.md edits require user sign-off (this phase).

### Phase 7 — Semantic lifting, hybrid builds, oracle verification (lift.py, hybrid_build.py, worklist.py verify)

Goal: give the unmatched tail a **semantic C scaffold** and a **runnable hybrid
image**, so the behavioral oracle can run at full coverage long before full
matching. Lifted code is NEVER byte-exact and NEVER counted as matched/honest —
that invariant is enforced by `audit.py`, not by convention.

- **`tools/lift.py`** — `lift <addr>` / `batch [--limit N --budget B]` (resumable,
  state `logs/lift/`) / `targets [--filter ...]` (offline: unmatched, source_lost,
  no-twin) / `status` / `report [--json]`. Capstone ARM-mode disassembly from the
  start to the next start; pool words split like `fn.py code_end`; tokens reuse
  the shapemine vocabulary (cond stripped, r/#/POOL/CALL). Per-function CFG,
  emitted as register-machine C: r0-r3 parameters, r4-r12/sp/lr zero-initialized
  locals, NZCV flag locals, frame as a local byte array, `bl` to a start ->
  `extern u32 func_XXXXXXXX(...)`, non-start `bl` (e.g. `__aeabi_idiv`-family
  helpers) -> opaque extern + warning, tail `b` -> plain call, jump tables ->
  switch, `bx lr`/`pop {pc}` -> `return r0;`. Anything unexpressible ->
  `/* LIFT-UNSUPPORTED */` stub (frame preserved, fixed return) with the reason
  in the batch state: a correct gap is acceptable, a wrong lift is not. Output
  files carry the LIFTED banner and live at `src_lifted/func_<ADDR>.c`; lifting
  records `status: "lifted"` in functions.json and nothing else.
- **Ledger** — `audit.py` accepts `lifted` (src_lifted/ path + cc, exists and
  git-tracked) and `semantic_match` (path + required `wall_class` from
  `scheduling|regalloc|pool_layout|unknown`); matched entries pointing at
  `src_lifted/` are rejected; both statuses are excluded from all
  matched/honest/hack arithmetic; the README table has an always-present
  "Lifted (semantic, not byte-exact)" row. `worklist.py register` refuses
  `src_lifted/` sources outright; `fn.py check` on a lifted file is
  informational only and cannot flip a status.
- **`tools/hybrid_build.py`** — assembles three layers at original addresses
  into `build/hybrid.bin` (never `code.bin`): matched sources recompiled by
  importing `rebuild_check.assemble_image` (not forked), lifted stubs compiled
  with their recorded cc/flags under the repo compiler lock (`--jobs 1`, one
  armcc call per function, objects cached in `logs/hybrid/obj/` — separate from
  the gate's cache so a lifted stub can never masquerade as a matched object),
  original `code.bin` bytes (SHA-1-verified, read-only) for the rest. `--check`
  is a fully offline composition plan (matched/lifted/original bytes +
  per-region coverage). The output is a **testing artifact for the oracle, not a
  release artifact**; the image gate is unchanged.
- **`worklist.py verify <addr>`** (roadmap C2+C3) — resolves a candidate
  (lifted stub, refine near-miss, or `--src`), emits a `RECOMP_OVERRIDE`
  skeleton under `logs/verify/<ADDR>/`, runs `behavioral_oracle.py`
  (3dsrecomp verify) against the Zakuro replay corpus in `logs/coverage/`
  (`ZAKURO_RECORD`/`ZAKURO_REPLAY`). Serialized, budgeted (`--budget`, default
  1 oracle run), resumable. A pass on a git-tracked candidate records
  `semantic_match` + `wall_class` in functions.json — byte diffs remain,
  behavior equal on the corpus; it stops near-miss budget burn without fake
  wins and never counts toward honest bytes. Without corpus/harness/ROM it
  prints the exact setup commands and exits non-zero. **First eligible
  candidates: the parked walls 005AB1D0, 0059F7B8, 005A8AA0, 005CBE9C.**
- **Decisions recorded:** (1) the register-machine C model was chosen because
  it is semantically faithful and compiles under armcc 4.1 `--c99` without GNU
  extensions; (2) hybrid builds keep a separate object cache (see above);
  (3) `verify` publishes `semantic_match` only for git-tracked candidate paths,
  preserving the audit's tracked-path invariant — untracked near-miss verdicts
  stay in `logs/verify/`; (4) the worklist lock is not reentrant, so
  `record_semantic_match(locked=True)` is used under `verify`; (5) the README
  was regenerated with `audit.py readme --write`, which also picked up master
  registrations that had not refreshed the table.
- **Non-goals:** no byte-exactness for lifted code, no auto-registration path,
  no change to matching criteria or honest/hack definitions, no host-layer port
  (F2 stays parked), no new dependencies.

### Phase 9 — Repair proposal pass (tools/proposals_repair.py + refine.py, roadmap H3)

Goal: a better proposal source for the reharvest near-miss queue (OP 1–3 words
from a match). `tools/proposals_repair.py` is a pure, offline, stdlib-only module:
given a candidate source text (+ optional diff metadata from the refine state)
and the target's known flags, `propose(source, name, diff, flags, budget)`
returns an ordered list of variants, each `{name, family, reason, hash, source}`,
each altering ONE thing armcc 4.1 is sensitive to. **Proposes, never judges:**
nothing in the pass compiles, checks, or registers; only `fn.py check` (armcc,
on the phone) judges a variant, and only `worklist register` records a
`RESULT: MATCH`. This stays inside the non-goal "tools propose, the oracle
decides" — no variant is ever auto-applied to a registered source.

- **Pass families, ranked by the repo's parked wall classes** (variant #1 is
  the most probable fix):
  1. `literal_value` — literal value nudges driven by the diff's differing
     words when available (wall: `neg-fam-sti-third-pool-word` and any pool-word
     OP delta; literals in pointer-arithmetic position are never nudged);
  2. `branch_arm` — `if (c) T else E` → `if (!(c)) E else T`, plus the flipped-
     comparison form `a == b` → `a != b` (walls: `neg-if-converted-guard-chain`,
     sweep's PERM branch-cond-flip class). Guards with assignments/`++`/`--`
     are skipped — the swap must stay provably side-effect-equivalent;
  3. `bool_cast` — explicit `(s32)(guard)` on if-conditions
     (wall: `neg-bool-materialized-guard`);
  4. `arg_register` — `register` storage-class hints on params/locals,
     signedness-invariant param type nudges (only when every use is a `==0`/`!=0`
     test), and param reorder for adjacent same-type params whose only uses are
     the two operands of one commutative op (an alpha-rename: semantics kept)
     (walls: `neg-stack-arg-frame-copy`, arg-carrying REG deltas; at `-O2` the
     `zero-loop-r2` recipe makes register/lifetime carrying outrank branch
     layout, so the family order promotes `arg_register`/`lifetime` then);
  5. `lifetime` — hoist a nested declaration to function scope (init kept at
     the original site), split a top-level local into a fresh *used* phase local
     after its 2nd assignment (the "dummy-adjacent" lifetime, but never a dummy:
     the fresh local must have a later use), narrow a declaration into its
     single use block. Loops/gotos/labels/`&x`/shadowing skip the rewrite;
  6. `operand_order` — commute `A op B` only for commutative ops with pure
     (identifier/literal) operands (REG-class allocation-only deltas);
  7. `cast_insert` — explicit `(uN)` cast on a store RHS matching the store
     width (truncation / bool-materialization);
  8. `literal_type` — `(u32)` cast / `u` suffix on integer literals (pool-word
     typing);
  9. `volatile_move` — relocate an existing `volatile` from a pointer
     declaration to its simple deref sites (never introduces one).
- **Semantic safety:** a pass that cannot prove the rewrite semantics-preserving
  emits nothing ("when in doubt, do not emit"); every variant is a full source
  string and carries a human-readable `reason` naming the sensitivity it targets.
- **Determinism and budget:** the enumeration is deterministic given the
  source; `--repair-budget N` (default 12, `DEFAULT_REPAIR_BUDGET`) caps
  variants per target per wave.
- **refine.py wiring (opt-in, additive):** `refine 0xADDR --proposals repair`
  adds the pass; ranking is after the dna-twin baseline/waves and before the
  synth fallback, and the pass re-proposes from any new winning body. State
  under `logs/refine/<addr8>/` gains new keys only: `repair` (proposed /
  skipped / families / seconds / budget), `proposals` (per checked variant:
  name, family, reason, hash, wave, match — so a phone MATCH traces back to the
  exact pass) and `rejected_hashes`. Rejected hashes are read back (never
  written by the pass) from refine state plus the permuter's tried-candidates
  cache `logs/permuter/<addr8>/tried.txt` when present, so a rejected variant
  is not re-proposed. Default `refine` behavior (no flag) is bit-for-bit
  unchanged, including the state shape. `refine.py propose [0xADDR ...]
  [--src PATH] [--repair-budget N] [--diff FILE.json] [--json]` is the offline
  batch surface: per target it prints variants proposed (with family and
  reason), skipped (cache/duplicate), and time spent — it never compiles.
  With no addresses it sweeps the logged near-misses (`logs/refine/*/state.json`
  with a best and no MATCH, closest OP first).
- **Upstream reference and license:** pass design (single-change variant
  families with reasons, propose-never-judge, per-family budgets, dedup by
  source, rejected-candidate interop) is ported from
  [RetroReversing/decomp-repair](https://github.com/RetroReversing/decomp-repair),
  licensed **AGPL-3.0-only** (`LICENSE`; some of its readers began in
  decomp.wtf, `LICENSE-decomp.wtf`). **No source from it is committed to this
  repo** — only the ideas, adapted to armcc 4.1 sensitivities; its
  MIPS/PS1/PS2/PSP/MSVC-specific passes (asm readers, GTE macros, CP0 leaves,
  `permuter_gen`) are dropped. Its compiler-specific rewrites that assume GCC
  or other compilers are not ported either.
- **Acceptance (offline, CI):** 24 unit tests on synthetic near-miss sources
  (no game content): determinism, family ordering, budget, reason strings,
  semantic-safety guards (arm swap only side-effect-equivalent, commute only
  pure commutative, split never a dummy, loop/assignment guards), `--json`
  schemas, resumability, rejected-hash interop, and a default-behavior test
  (no new state keys without the flag). The compile-and-judge loop is a phone
  checklist (see the PR description), not part of CI.

## Ordering, effort, risk

| Phase | Effort | Risk |
|---|---|---|
| 1 dna finish | hours | low — pure local analysis |
| 2 recipes | 1 session | low — data entry from LESSONS/matches |
| 3 synth | 1-2 sessions | medium — class coverage grows with use |
| 4 refine | 1-2 sessions | medium — acceptance test gates it |
| 5 queue | 1 session | low — glue over finished pieces |
| 6 AGENTS.md | minutes | sign-off needed |
| 7 lift/hybrid/verify | 2-3 sessions | medium — full mode needs code.bin + armcc + the Zakuro corpus on the phone; the offline parts (targets / hybrid --check / tests) are gated here |
| 9 repair proposals | 1 session | low — pure offline generation; the judge stays `fn.py check` on the phone (phase 8 is the sdkmap session's) |

Phases 1–2 unlock value immediately (dna twins alone close functions);
3–5 are what actually removes the expert from the loop; 6 is cheap but must
come last so the documented loop is the real one.

## Non-goals

- No LLM-in-the-loop automated mutation of source text by tooling — the
  agent (whatever its size) stays the editor; tools propose, agent applies.
- No network/decomp.me dependence; everything is local.
- No batch-compile of many files per wine call beyond what sweep.py does —
  the oracle stays ~5-9 s/function and budgets respect it.
