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
| Matched, source included | 16,934 | 65.2% | 1,440,156 | 24.7% |
| of which honest (no hack) | 16,151 | 62.2% | 1,315,020 | 22.5% |
| of which hack | 783 | 3.0% | 125,136 | 2.1% |
| Earlier match, source not included | 114 | 0.4% | 15,396 | 0.3% |
| Not matched yet | 8,924 | 34.3% | 4,380,880 | 75.0% |
| Excluded library | 14 | 0.1% | 4,748 | 0.1% |

Remaining for an honest decompilation (excluding libraries): **9,821** functions.

Sizes use consecutive starts in `funcs.json` within `.text` (`0x100000`–`0x69211C`), not the whole binary.
3 interior-address entries are not counted as separate functions.

Hack reasons (a function can have several): weak 527, __schedule_barrier 156, asm 94, identical_arms 22, perm_t 15, dummy_local 12, volatile_dummy 3.
<!-- /generated:status -->

**Correction to the first publication.** 419 entries of the first publication (2026-10-15) were removed after a
relocation audit. The old checker masked relocated words and could print `RESULT: MATCH` for the wrong call or global.
The checker now validates supported relocation identities and rejects unknown symbols, unsupported relocations,
and unproved linker rewrites. Existing entries have **not** all been reverified with this stricter checker;
the table reflects recorded metadata, not a new verification campaign.

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
| `shared/include/` | Project headers (written for this project) |
| `shared/symbols.jsonl` | Names inferred for some functions |
| `shared/extra_starts.txt`, `shared/not_starts.txt` | Corrections to the function table |
| `funcs.json` | The function table: start addresses, call targets, pointers. Addresses only, no code |
| `tools/fn.py` | Disassembly, cross-references, and the byte-exact checker |
| `tools/audit.py` | Offline invariant audit of `functions.json` + status-table stats |

## Requirements

1. **Python 3.10+**. Install analysis dependencies with `python3 -m pip install -r requirements.txt`.
   Offline tests, audit, and worklist `status`/`report` require only the standard library.
2. **The game code binary.** Save it as `code.bin` in the repository root. It is the decompressed `.code` section of
   the USA release, dumped from your own copy, 6,455,296 bytes, SHA-1 `e6ab7d66ee62e879248b0660aaf38d22202e604b`.
3. **ARM Compiler (armcc) 4.1, build 1049.** Place it at `tools/armcc/4.1/b1049/bin/armcc.exe`. Every published
   function uses this build unless its index entry specifies otherwise. You need your own licensed copy.
   On Linux/macOS, the Windows executable also requires Wine (available as `wine` on `PATH`).

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
- **وين وصلنا:** 16,934 دالة لها مصدر (65.2%)، منها 16,151 نظيفة (62.2%) و783 بحيل.
- **وش باقي:** 8,924 دالة غير مطابقة؛ الباقي لتفكيك نظيف، باستثناء المكتبات، 9,821 دالة.
<!-- /generated:arabic-status -->
- الأرقام من الفهرس؛ لم تُعَد مراجعة كل المصادر بالمُدقّق الجديد الأكثر صرامة.
- **وش ما يشمل:** ما فيه أي ملفات من اللعبة (ملف الكود أو ملفات البيانات) ولا المترجم. كل واحد يجيب نسخته بنفسه.
- **ليش منشور:** الشغل منشور عشان أي أحد يبي يكمّل.
