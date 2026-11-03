# Lessons: what worked, what did not

All numbers below were measured with the byte-exact checker on this game.

## What worked
- **Many independent per-function attempts, each verified by the compiler.** This produced most of the matched
  functions.
- **Twins.** A function byte-identical to a matched one, or identical except for constants and offsets, reuses that
  source with the values substituted.
- **Build flags per function.** About 850 functions only match with `--apcs=/fpic`, which never emits tail calls. Many
  matches that had used `weak` prototypes just to block a tail call became honest under `/fpic`.
- **Removing the hack and re-checking.** About 76 matches had used a `__schedule_barrier` or a dummy local that turned
  out to be unnecessary. Without it, the source still matched.
- **Batch compiling.** Passing many files to one compiler invocation was about 20x faster than one process per file.
  Output was identical in every order we tested (500 files, forward, reverse and shuffled), once object and section
  names no longer depended on the batch position.

## What did not work on the remaining functions
- **Lifting machine code to C, then repairing it locally.** On random unmatched functions: medium 18 of 233 (7.7%),
  large 1 of 119, huge 0 of 30. The lifted C is shaped like the machine code; the original source is not.
  Differences are coupled: control flow, value lifetimes and calling details change together, so small independent
  edits do not converge.
- **Learning rewrite rules from (lifted output, true source) pairs.** 0 reusable rules from 250 pairs.
- **Locking and transplanting single-entry/single-exit regions from matched functions.**
  - Transplants alone: the total byte difference fell by 65% (1,603 to 564), but 0 functions matched fully.
  - Per-region mixing of several lift variants: 0 new locked regions.
- **A constructor/destructor synthesiser.** 15 of 20 small ones (8-64 words) matched, but 0 of 40 larger ones.

## Measured compiler behaviour (armcc 4.1 b1049, from compiling test sources)
- `--apcs=/fpic` never emits a tail call. It also makes global data addresses pc-relative.
- A `weak` declaration of a callee stops tail calls to it. About 500 matches still need this. Their callees are never
  tail-called anywhere in the game, so the original headers probably declared something that has the same effect.
  We could not find a non-weak declaration that reproduces it. A systematic sweep of candidate constructs
  (2026-10-25, armcc -S, target shape `BL callee` + `POP` instead of tail `B`) eliminated: `__declspec(noinline)`
  (with or without `--apcs=/interwork`), discarded int return, variadic callee, `__softfp`, `--exceptions`,
  `--no_rtti`, `--Ospace`, `--no_inline`, `--no_autoinline`, `--no_early_inlining`, `--split_ldm`, `--no_split_ldm`,
  `--lower_ropi`, `--pointer_alignment=1`, `--shared`, `--no_rtti_data`, `--vfe`/`--no_vfe`,
  `__attribute__((interwork))` (ignored, warning #1207-D), `__interwork` keyword (does not compile), same-TU
  `__declspec(noinline) __inline` definition (emits a non-weak EXPORT but still tail-calls), `#pragma no_inline` +
  `__inline`, a large `__inline` body (fully inlined instead), a call inside an `if` block, an empty inline dtor
  local, and a dead-store dtor — none stop the tail call. Partial effects with the wrong shape:
  `__attribute__((noreturn))` callee gives `BL` but deletes the epilogue `POP`; a try/catch around the call gives
  `BL` but adds catch-handler machinery; a real call after the target call gives `BL`+`POP` but the trailing call
  is itself tail-called. One coupled effect remains unexplained: in func_0011F95C (manual dynamic_cast), a weak
  callee also turns the `__cxa_guard_release` call site into `mov r0,r0` while leaving its literal load intact;
  removing the release call without weak makes the diff worse. Do not re-test these; remaining hypotheses are
  (a) the original headers genuinely declared these callees weak (CTR-SDK hookables), which would make `weak`
  a faithful reconstruction, or (b) an unguessed build-system property (per-TU --via files, post-link patching).
- armcc 4.1 has **no coprocessor intrinsic**: `__mrc(15, 0, 13, 0, 3)` is treated as an implicit function
  (warning #223-D, emits `IMPORT __mrc`), and the shipped include tree has no mrc/mcr intrinsic header.
  The 82 `asm` hacks are all `mrc/mcr p15, …, c13/c0` TLS thread-pointer reads/writes (69+ are exactly
  `mrc p15, 0, t, c13, c0, 3`); the instruction is semantically required by the target bytes, so these cannot
  be de-hacked by construct substitution. The plausible honest resolution is that the original SDK headers
  used inline asm for TLS access — a project-level reclassification with evidence, not a per-function fix.
  No honest-matched source in the repo contains `__asm`.
- Temporaries and named locals give different code (store pairing, slot reuse). Stack frame offsets follow the
  declaration order.
- Constructors and destructors return `this`, and chains reuse the returned register. An inlined member destructor
  that only stores a vtable pointer is removed as a dead store.
- Floats are passed in VFP registers.
- A `return CONSTANT` on the null path of a guard (fn 003C8BB8, verified 8/8) emits
  `CMP r0,#0; LDREQ r0,=CONST; BEQ past_fallthrough; …; BX lr` + pool word. The
  pool word loads into the RETURN register and the branch skips to the trailing
  `BX lr`: i.e. the constant IS the return value. Same shape works for any
  error-code-returning accessor in front of a virtual dispatch `(*(Fn**)c)[i](c)`
  (emission: `LDR r1,[r0]; LDR r1,[r1,#i*4]; BX r1`).
- A guard `if (!c) c = &default_obj;` then dispatch emits `CMP r0,#0; LDREQ r0,=addr;
  LDR/LDR/BX` WITHOUT a BEQ (the dispatch is shared by both paths) — distinguishable
  from the error-code shape above by the missing `BEQ`.

## The main blocker (the conclusion of a final small study)
For the remaining functions, the bytes reveal the calling-convention level reliably:
- the argument count, stack arguments included;
- the return type;
- the value on the failure path;
- the store order.

They do **not** reveal the exact source form of inlined helpers: constructors, setters taking parameters, reference
parameters, temporary objects, conversion operators. Each site leaves 2-3 plausible forms, and the sites interact.
The best lever is therefore a correct, shared header library of the game's small inline helpers and classes. Each
helper recovered correctly helps every function that uses it.

## Misses and open problems

- `svc #N; bx lr` syscall stubs (e.g. 00100B88 svc#3, 0010D0EC svc#0x3c, five unindexed): armcc's
  documented `__svc(N)` construct is call-shaped — any wrapper compiles to `push {r4,lr}; svc #N;
  pop {r4,pc}` — never the frameless 2-word form the targets have. No known pure-C producer;
  likely SDK assembly or header inline-asm. Same for `ldr pc,[pc,#-4]; .word thumb_target`
  thunks (003C90C8 family): linker-generated ARM→Thumb veneers, not source functions. (current agents)

- `svc` write stubs (9× 24B, e.g. 00103C68, 0010EAE8): `str r0,[sp,#-4]!; svc #N; ldr r2,[sp];
  str r1,[r2]; add sp,#4; bx lr` — the arg is pushed to the stack, the svc returns a pointer in
  the stack slot, and r1 is stored through it. armcc's `__svc(N)` never produces stack-slot
  round-trips; variadic C can't reach svc. Skip as SDK assembly. (b24)
  Variant 0010BE9C (`push {r4,r5}; ldr r4,[sp,#8]; ldr r5,[sp,#0xc]; svc #0x22; pop; bx lr`)
  reads varargs off the stack into r4/r5 before svc — same SDK-asm family, skip.

- func_00691F18 (16B): `vmov s0,r0; vcvt.u32.f32 s2,s0; vmov r0,s2; bx lr` — a
  softfp float->u32 conversion helper that uses s2 as the conversion scratch.
  armcc 4.1 b1049 emits `vcvt.u32.f32 s0,s0` from every C shape we tried
  (plain cast; forced temp; --Ospace; -O2; #pragma O2; ternary; sizeof; second
  int/pointer arg; two-float signature with either arg converted). It never
  allocates a second VFP register for this. Plausible explanations: a different
  armcc 4.1 build (b561+), or one of ARM's EABI conversion helpers
  (__aeabi_f2uiz-style) compiled from runtime source with a different
  toolchain or hand-written. Revisit if a build other than b1049 is pinned or
  a neighboring helper family (f2iz/d2iz/f2iz) shows the same s2 pattern.

- func_0041DCF4 (24B): `mov r2,#0; add r3,r0,#8; str r2,[r0]; strd r2,r3,[r0,#4];
  str r3,[r0,#0xc]; bx lr` — empty-list head init (count=cap=0, next=prev=&next).
  [RESOLVED 2026-10-26, honest, commit 4f31932, src/work8/nosrc/func_0041DCF4.c:
  `void f(struct R* s, unsigned n) { s->cap=0; s->n.next=&s->n.next; s->n.prev=0;
  s->y=s->n.next; if(n) return; }` with `struct R { unsigned cap; N n; void* y; }`,
  `typedef struct N { void* prev; void* next; } N;`, default flags.]
  STRD-PHYSICS (b1049, ~200 probe compiles):
  1. STRD at [r0,#4] with pair (0, addr) ONLY fires for a NESTED-STRUCT pair
     `N{void* prev; void* next;}` — plain sibling fields (same layout!) never merge
     (always 2×STR, sometimes `str [r0,#4]!` writeback).
  2. The pair address must be the BACK- or SELF-anchor `&s->n.next` (a field of the
     pair itself) — an address with two TEXTUAL uses (`next=&next; y=&next`)
     DOES NOT merge; the SECOND use must be a LOAD `s->y=s->n.next` written
     AFTER the pair statements. The load folds to the same register (no LDR),
     but schedules its STR last — giving the target's strd-then-str(+0xc) order.
  3. REG ALLOCATION: `mov r2,#0` first / `add r3,r0,#8` second needs a 2nd param
     `unsigned n` PLUS a provably-dead `if(n) return;` guard at the end (void fn).
     Without the dead branch: no STRD (STM via computed base, or writeback, or
     DCE-order changes). The dead branch changes block-boundary store batching.
  4. Statement order that wins: `cap=0; next=&next; prev=0; y=next-load;` —
     y-load LAST is essential; cap FIRST puts its STR before the STRD.
  Sizes: no return-this needed (void). Same trick family likely applies to other
  STRD-pair targets (00169A28 already honest via live-arg r2 trick).
- func_00169A28 RESOLVED honest (see lessons): `mov r2,#0; 4×str r2,[r0,#N]; bx lr`.
  The honest keep-producer for the r2-zero: a second parameter live across the zero-init
  (`if (n) self->m0 = 0;` — even dead) at -O2 -Otime. Context: vec-new element ctor
  (call site 0x16A454, element size 0x14, ctor ptr in r1, count in r3 via blx 0x100118).
  Lesson: grep literal refs (ptr table, literal pools) for the address FIRST — the call
  site gives the signature; brute-forcing register allocation blind wastes hours.
  ~15 C source shapes tried (field order permutations, chained assignments, node
  temp, struct-copy of an 8-byte sub-struct, u64 shifted value, C++ ctor init
  list — inlines to nothing). armcc b1049 emits STRD for two adjacent u32 stores
  only when both values are already in registers with no intervening address
  computation (verified in matched 00102FB4: strd r0,r4,[r4,#4] for two in-reg
  args); otherwise it prefers STM+ADD or STR writeback tricks and never merges.
  The target's exact form (STRD at [#4] + MOV r2/ADD r3 allocation) was not
  reproduced; revisit with a C++-specific shape (e.g. out-of-line ctor, this
  pointer offset) or a different field-type hypothesis.

- func_00560E5C (24B, unindexed, relocation-table resolver; callers pass
  (&stack_local_holding_relocated_base, idx)): `mov r2,#4; add r2,r2,r1,lsl#2;
  ldr r1,[r0]; ldr r0,[r1,r2]; add r0,r0,r1; bx lr` = `*(u32*)(*pp + 4 + idx*4) + *pp`.
  Unmatched after ~90 source shapes (g/m/i/j/k/n series, default flags + -O1/-O2/-O3/-Otime,
  fpic/norwpi/no_remove, softfp, all armcc 4.1 builds b561-b1454 sweep on i31).
  PHYSICS (b1049):
  * Plain/struct/volatile/commuted shapes all allocate base=*pp -> r0 (the dead
    pp's own register, same-reg load), off -> r1, value -> r1/r0 at add order.
  * Target's reverse allocation (off->r2 via MOV r2,#4 first, base->r1 reusing
    idx's register, value->r0) needs pp to stay live across the base load, which
    no honest source achieved: a second *pp use forces a reload (extra LDR),
    volatile forces base->r2 but then off->r0/r1 and order flips (base load first).
  * Guard-on-pp shapes (m01: `if (pp) return v+base; return v;`) give the exact
    order+regs (6/7 words) but keep `cmp r0,#0; addne` — armcc cannot fold a
    pointer null-check; guard-on-off/on-idx does not keep off in r2.
  * ADD commutativity is normalized in codegen (base+v == v+base identical).
  * Ordering: -O1/-O2 keep source order only with a separate off local declared
    first; -O3 hoists the base load first unless a condition pins pp.
  Best honest shapes for reference: i31 (`u8* bytes = (u8*)*pp; off local;
  *(u32*)(bytes+off) + (u32)bytes`) = same ops/op-order but base->r0;
  m01 -O2 guard = 6/7. Likely a different build/inline-asm; do not brute-force.

- VFP bulk-copy family in 0x115xxx (001151D8 getRot, 00115234, 001150B8, 001150CC,
  00115AC8): the codegen rules for b1049 VFP struct/array copies, established
  empirically (all with --cpu=MPCore, flags -O3 -Otime and -O2/-O3 +-Ospace/-Otime
  tested):
  * Bulk VLDM/VSTM of N regs comes from the **all-used float locals pattern**
    (v0..vN-1 = src[i]; dst[i] = vi) — see matched 001151EC (12/12) and 00115224.
  * Struct copies (direct or via tmp) always chunk at **8 regs max** ({s0-s7}
    twice); via-tmp 16-float copies give one merged {s0-s15} pair. C++ operator=
    memberwise goes **core regs** (LDR/STR), never VFP.
  * **Writeback (vldmia/vstmia rX!) only appears when a pointer variable is
    advanced between reads and used again** (p += 12; then read p[0..3] folds the
    WB into the first load), or **when the advanced pointer is returned** (return
    dst+16 folds vstmia r0!). Proof: matched 00115224. A dead advance is DCE'd
    (no WB); a second load from a *different* base never triggers WB on the
    first — 00115234 (`vldmia r1!,{s0-s11}; vldmia r2,{s12-s15}; vstmia r0`) is
    1 bit (W) away from the plain-locals form and no C shape produced that WB
    (indexed locals; p+=8/-index re-read; per-element *p++ — splits into 11
    single WB loads; b-loads-first; Ospace/Otime/O2 variants). Revisit only with
    a new WB mechanism idea.
  * **Dead loads are always eliminated**: unused floats (translation column of
    Mtx34 in getRot 001151D8) are never loaded at -O1/-O2/-O3 (-O1 keeps VLDR
    pairs only for *used* floats; -O0 goes core-regs + stack). The target's
    `vldmia r1,{s0-s11}` with s3/s7/s11 dead + 3 separate WB vstmia groups has
    **no honest C producer found**; likely hand-written asm or another armcc
    build. Do not brute-force again. (2026-10-26: for the 12+4 two-base fn
    00115234 the "another build" escape is now ruled out — the no-WB fb-locals
    emission is **byte-identical across all nine armcc 4.1 builds we have**
    (b561 fails to run; b713/b791/b844/b894/b921/b1049/b1440/b1454 identical),
    and identical across -O1/-O2/-O3±Otime/--fpu=vfpv2/--fpu=vfpv3/-Ospace.
    Dead-bump matrix: `p += N` before/between/after the loads is ALWAYS DCE'd
    at -O3±Otime. Remaining hypotheses for the r1! bit: hand-written asm, an
    unknown pragma, or a construct class outside the probed space.)
  * A **guarded 2-op VFP body is always predicated** (CMP; VLDMNE/VSTMNE; BX) —
    never the target's `CMP r1,r0; BXEQ LR; vldmia; vstmia; BX` branch form.
    Guard forms tried: if==return, if!=body, guard-in-loop, tmp vs direct copy,
    value-returning — all predicate (>=4-op bodies branch but then the copy
    chunk-splits at 8). `bxeq lr` normally means early-return guard with a
    prologue after it. (2026-10-26 refinement for 001150B8, semantics confirmed
    by Ghidra: `if (param_2 == param_1) return;` + 16 floats):
    `if (s == d) return;` + 16 named locals gives **one more 16-wide producer**
    `CMP r1,r0; VLDMNE r1,{s0-s15}; VSTMNE r0,{s0-s15}; BX lr` (18B — exact cmp
    operand order and batching, everything except the predication form). -O1
    branches but scatters VLDRs; -O2/-O3±Otime all predicate. The BXEQ
    branch-form DID appear at -O3 -Otime with a **second live conditional
    return after the body** (`if (d[0]==0.f) return;`) but that pollutes the
    body (VPUSH {d8} + split VSTM r0!,). Foldable/do-while(0)/two-return
    variants all fold and predicate. No zero-instruction trigger found.
    C-library note: `memcpy(d,s,64)` (real string.h or manual prototype ±
    __declspec(__nothrow) ± __restrict) lowers to BUILTIN:
    `cmp r1,r0; bxeq lr; mov r2,#0x40; b __aeabi_memcpy` — a *tail call*, never
    the bl __rt_memmove_w trampoline and never VFP batches. So memcpy-sourced
    originals are eliminated for all batched-VFP targets in this family.
    001150B8 unproducible; likely another build or hand-written.

- 001150CC (15w) and 00115234 (4w): both need a **merged 12-float WB load
  (vldmia r1!,{s0-s11}) with NO subsequent use of the advanced pointer**.
  b1049 folds writeback only when the advanced pointer is used again (matched
  00115224/00115AC8: p += 12 between reads, or return of advanced dst).
  Contiguous p[0..11] reads + dead p += 12 gives NO WB; 3x4 row reads with
  p += 4 walks give 3 separate WB loads; per-element *p++ gives 12 single WB
  loads; loops split. 001150CC is otherwise 14/15 exact (scattered reversed
  stores + str r2 tag store at dst[1] all match). `--no_remove` does not exist
  in armcc 4.1. Revisit only with a new WB mechanism.

- 00115D70 (6w, `vldmia r1,{s1-s3}; vmul s4,s1,s0; vmul s5,s2,s0; vmul s6,s3,s0;
  vstmia r0,{s4-s6}; bx lr`, Vec3 scale-setMul): needs FRESH result regs s4-s6
  after a bulk 3-load, with operands s1-s3 dead after the muls. armcc b1049's
  allocator is forward-allocated (lowest free sreg): every source form (per-op
  stores; all-temps p/q/r; struct-copy tmp; aliasing branch guard; member fn;
  4-float w-load; dst==src check) emits in-place muls (s1*s1, s2*s2, s0*s3) and
  split stores (VSTR s0@8 + VSTM {s1-s2}). -O1 gives fresh s4-s6 ONLY with
  split VLDR loads (no bulk VLDM); -O2/-O3 give bulk load + in-place muls.
  The two mechanisms (fresh alloc + bulk load) never co-occur in b1049, and
  NOT in any 4.1 build (b561 spills via stack; b713-b1454 identical to b1049).
  b561 for simple shapes: 3x VLDR+VMUL in-place per-component, or all-locals
  3x VLDR {s1,s2,s3} + in-place. Likely hand-written asm or a build we don't
  have. Do not brute-force again. Scratch: $TMPDIR/v3/ v56-v74.

- Transform family 00115074 / 00115CA8 / 00115D18 (Mtx34 x Vec3, ~15-30w):
  targets bulk-load **all 12 matrix floats upfront** (vldmia r1,{s0-s11}) plus
  the 3-vector (vldmia r2,{s12-s14}), then 9 vmla/vmul + 3 scattered vstr —
  register allocation exactly follows declaration order (m->s0-s11, v->s12-s14,
  accumulators = the loaded translation regs s3/s7/s11). b1049 **rematerializes
  single-use float loads**: every source form tried (expression form; explicit
  chained +=; all-locals; struct-copy tmp M34 a = *m; loop over 3 rows; decl
  order m-first/v-after) and every flag combo (-O3/-O2/-O1, -Otime/-Ospace,
  --vectorize) interleaves 12 per-element VLDRs with the FMAs instead of one
  bulk VLDM. No matched function in the corpus combines bulk VLDM with
  VMLA/VMUL compute. This TU's style (upfront bulk load) may come from a
  different armcc build. The near-miss shape is: same FMA order (v-component
  outer, row inner), same accumulate-onto-translation semantics — only the
  load grouping differs.

- 0x100000-0x100B84 front block = CRT/startup (likely hand-asm or GCC): 
  - 00100000 (init chain, 9 words): bl x8 + bare `b` tail with NO lr save — the tail
    call to the svc stub with lr clobbered by the 8 bls is semantically broken, so
    it's not compiler-generated C. armcc's shape for the same source is either
    push{r4,lr}; bl x8; pop{r4,lr}; b (tail call needs the saved lr) or, with
    __declspec(noreturn) on caller or last callee, bl x9 with no saves (bl, not b).
  - 0010818C / 0010BFD4 (ldrex/strex sync primitives): 0010BFD4's else path runs
    clrex then FALLS THROUGH the section pad into the next function 0010BFFC —
    a linker-layout fall-through no compiler emits; 0010818C uses strex status
    ip with a dead ldrex dest r2, while armcc b1049 always reuses r2 for the
    status when ldrex's result is dead (status=ip only when ldrex value is live
    at the strex, e.g. matched 0010AE00). Both = kernel asm, skip.
- armcc b1049 loop transformation: `u32* p=start; while(p<end) *p++ = 0;` at
  -O3 -Otime becomes a counted unrolled loop (diff/8, str pairs, [r0,#8]!); at
  -O3 -Ospace it emits the naive `mov r2,#0; cmp r0,r1; strcc r2,[r0],#4; bcc`
  (this matched 00100024 — first -Ospace match in the project).
- fn.py comparator facts: BL->BLX by linker accepted when my word is bl with a
  call relocation ((tw>>25)==0x7D detects target blx-imm); tail `b` to next
  function turned into NOP (mov r0,r0) also tolerated via R_ARM_THM_JUMP24.

- 0010FC34 (strcmp-like, 13w): shape cracked but the range includes a trailing
  orphan data word 0x01010101 (no PC-relative load points at it from anywhere;
  linker-placed pool/constant). 12/13 words exact — the loop is
  `c1=*a++;c2=*b++; if (c1!=c2||c1==0) break;` x2 manually unrolled with armcc's
  flag fusion cmp r2,#1 / cmphs r2,r3 / bne (the fusion appears for &&/-condition
  forms; `||`-in-if compiles to separate cmp/beq pairs). Unproducible trailing
  constant -> skip. Also: armcc at -O3 -Otime does NOT auto-unroll this while
  loop; the unroll must be written in source.
- 0010F924 (struct zero init + (0,-1) STM pair, 13w): 11/13 near-miss. armcc
  -O3 -Otime allocates zero=r1, addr(+0x1c)=r3, minus1=r2; target has
  zero=r3, addr=r2, minus1=ip. -O3 -Ospace shifts to addr=ip, minus1=r3 (still
  zero=r1). No source form found that puts the first-materialized value in r3
  with r1 free; both callers unindexed (no signature oracle).

- 0010DA3C (64B polymorphic ctor with intrusive empty list head, near-miss, NOT
  brute-force orders again): target = `mov r2,#0; ldr r1,poolA(vtable); ldr
  r3,poolB(ro ptr); str r1,[r0]; strb r2,[r0,#4]; strd r2,r3,[r0,#8]; add
  r3,r0,#0x14; add r1,r0,#0x10; stm r3,{r1,r2}; str r1,[r0,#0x10]; str x3`. 
  Findings: (a) field x=0,y=&ro pair as plain assignments NEVER strd-merges in
  armcc at any level/order (~12 source permutations tried: flag/x/y/vptr orders,
  init-lists, temp-struct copy, -O2/-O3/-Otime/-Ospace); armcc always splits and
  hoists pool loads late with base-advance store tricks. (b) u64 field assigned
  `(u64)&ro << 32` DOES hoist both pool loads to the top (closest shape) but
  still splits the 64-bit store into two STRs (lo r1, hi r3) and puts the vptr
  store 6th. (c) compiler-inserted vptr store is NOT emitted first by armcc when
  the ctor body assigns fields (it schedules with the rest). Target's strd
  r2,r3 with lo=0/hi=pool remains unexplained (same family as 0041DCF4).
- 0010FC34 (52B strcmp-style fused loop, 12/13 words): target fuses
  `c1!=0 && c1==c2` into cmp r2,#1 + cmphs r2,r3 with 2x unroll (bne-exit then
  beq-loop). Plain `while (c1 != 0 && c1 == c2)` gives separate cmp/beq pairs
  (no fusion, no unroll); manual `if (c1 != c2 || c1 == 0) break;` unrolls but
  does not fuse. The last word 0x01010101 is orphan linker data (no PC-relative
  user anywhere in +-4KB) — unproducible trailing constant, function unmatchable
  as bounded.

- **Copy-variable blocks armcc's guard/copy subs-fold** (proof: matched 0010B380
  and oracle 0010A644): a source-level guard `if ((s32)n_arg <= 0) return;` on a
  param that stays live across a call otherwise compiles to
  `push; subs rX,n,#0; ble` (armcc fuses the callee-saved copy with the
  compare, placing the test INSIDE). Writing `u32 n = n_arg;` (an explicit copy
  local used afterwards) prevents the fuse and yields the pre-prologue exit
  `cmp rN,#0; bxle lr; push; ...; mov rS,rN`. A bare `(s32)` cast does NOT
  prevent the fold.
- **STM base reveals struct layout**: `stm r4,{r1,r5}` with NO base advance means
  the stored fields are at offset 0/4 of the base register; an adjacent
  `str r0,[r4,#8]` is a separate field at +8, NOT contiguous with the stm pair
  (stm has no offset encoding — offsets come only from base advance). When
  armcc instead 3-merges into one stm with `add base,#8`, your inferred layout
  is probably wrong.

- 0010D370 (MI ctor, 14/16): `D : B1, S` with B1 = 12-byte polymorphic
  primary {vptr,x,y} (inlined ctor), S = 0010DECC's class (out-of-line ctor at
  self+12, size 0x20C), members f1/f2 at +0x218/+0x21C zero-initialized.
  Everything matches EXCEPT the post-call vptr-pair allocation: target
  `ldr r1,[pool2=Dvt]; add r2,r1,#0x20` (forward order), armcc emits
  `ldr r2,[pool2]; add r1,r2,#0x20` (reverse order) in EVERY variant: plain
  6-virtual B1, B1-with-virtual-dtor, explicit base calls, body assignments,
  S with 3 virtuals, D overriding B1::v1, B1 ctor out-of-line, no_inline S
  ctor, --no_exceptions/--rtti/--vectorize, -O2 (different shape: pool reuse
  in r1 but self-add + pre-indexed no-WB store + wrong order), -O3 -Ospace,
  and ALL builds b561/b713/b791/b844/b894/b921/b1440/b1454. D adding a new
  virtual or virtual dtor APPENDS a vtable slot (secondary offset becomes
  0x24/0x28) and inlines S's ctor — wrong shape. armcc regalloc assigns
  registers at definition in reverse-definition order for this pair; no tested
  source form flips it. The target's pool→r1/add→r2 regpair DOES occur in a
  different context: 0010C51C's inline base-ctor `stm r0,{r1,r2}` (two
  adjacent vptrs at +0/+4, two near-empty polymorphic bases) — not
  transferable to a most-derived vptr-pair store after a BL.
  Scratch: $TMPDIR/mitest/{t1-t5,v1,v2,w1,w2,w5,m1,m2,x4,x5,x6}.cpp.

- **0010E250 MATCHED honest (17/17)** via a chain of discoveries — the recipe:
  (a) It is NOT a ctor but an init-method `D* D::initialize()` whose source
  literally returns `(D*)((char*)k - 0x24)` from the callee's return: that is
  what makes armcc emit `mov r4,r0 ... sub r0,r4,#0x24` (raw retval saved,
  this derived at the END). A C++ ctor instead remats this EARLY
  (`sub r4,r0,#0x24` right after the ctor BL then `mov r0,r4`) — the exact
  15/17 near-miss of the ctor interpretation.
  (b) The callee must be a member function returning its own `this`
  (`Key* Key::init()`), NOT a ctor: only then is the return value usable in
  source and chainable (`k->set(v)` reuses r0 from the BL directly).
  (c) **-O2 -Otime** is required (not -O3): at -O2, a LOCAL `u32 v = 0;`
  passed as a call arg is kept in a callee-saved reg across a BL
  (`mov r5,#0` early; `mov r1,r5` at the call). At -O3 the constant is
  re-materialized (`mov r1,#0`). b1049 otherwise ALWAYS remats literal call
  args; the local-variable-at--O2 form is the honest producer of
  keep-across-call + mov-copy (verified: 0 corpus oracles for keeping an
  immediate across a call).
  (d) The empty circular list stores come from a POINTER-LOCAL in the
  function body: `Node* p = &root; p->prev = p; count = 0; p->next = p;
  z = 0;` — this exact source order yields the target's
  `add r2(&root); tag-store; add r1(=prev/base, REUSING the pool reg);
  mov r5,#0; stm r1,{r2,r5}; str r2,[r0,#0x14]!; str r5,[r0,#0xc]!`
  sequence (stm merge + two-WB chase building &key). Every other authoring
  order loses the stm or the writeback chase.
  (e) push {r4,r5,r6,lr} = armcc pushes r6 (unused pad) whenever TWO
  callee-saved values are live (proof also 0010B380); one value → push {r4,lr}.
  (f) Pool loads for explicit `tag = (u32)ro[]` assignments hoist pre-push at
  -O2 -Otime only in this flat/init-method shape; in ctor shapes armcc sinks
  them late (cf. 0010DA3C open problem).

## tools/sweep.py — parallel variant sweeper with diff classification (2026-10-26)

`python tools/sweep.py <addr> <spec.py> [--jobs N] [--sample N] [--max N] [--stop-on-match] [--top N]`
drives variant-matrix hunts on top of permuter.check_one (killpg-safe wine).
spec.py: TEMPLATE with @@SLOT@@ tokens (braces clash with C), GRID {slot: [texts]}
(cartesian), GROUPS [dicts] (coupled substitutions — e.g. helper
signature+body+call must change together), BODY (list of statements swept over
orderings; n! > sample → seeded random sample, NEVER materializes n! — 12! =
479M tuples OOM-killed Termux once), FLAGS (list of flag strings).

Diff classifier parses fn.py check's diff table per variant:
- OP: instruction really differs (mnemonic/immediate) — construct wrong
- REG: same instruction modulo register names — allocation-only delta
  (cross-TU `bl #x` target diffs from unresolved extern names count as REG,
  fn.py prints them unmarked)
- PERM: whole function one reordering of the same instruction multiset
- b-pairs (bne vs beq etc.): counted once as OP; if multiset matches modulo
  branch condition codes and n_reg==0 → PERM with OP zeroed (flip fixable
  by swapping if/else arms)

Parser pitfalls learned: diff rows can carry TWO offset columns (grouped
table when sizes differ); bare hex offsets ("c") must not be parsed as
mnemonics (require >=2 letters or "b"); missing-side rows count as OP.

003C8BB8 (32B virtual-dispatch getter) was matched by hand with:
`if (!c) return 0xE0E046BC; return vtbl[5](c);` — null path RETURNS the pool
literal (pool load on the return-critical path, beq skips the loads). A pure
fallback-object shape (`if(!c) c=&default_obj;`) folds both paths (no branch)
and misses. When a null-return path loads a pool constant, put the constant
on the path as the return value.

## 00106FC4 (84B composite ctor) — construct settled, allocation open (2026-10-26)

Target: `push {r4,lr}; bl construct; add r3,r0,#0x5c; add r1,r0,#0x58; mov r2,#0;
stm r3,{r1,r2}; mvn r3,#0; str r1,[r0,#0x58]; str r2,[+0x68..0x70];
add r4,r0,#0x7c; strd r2,r3,[r0,#0x74]; mvn ip,#0xff000000; stm r4,{r3,ip};
mov r1,#1; strb r1 ×3 [0x84..0x86]; str r2,[0x64]; pop`.
Best source (v251): `__inline setP(P*t,void*l,int z){P tmp; tmp.p=l; tmp.z=z; *t=tmp;}`
(STM merge) + `__inline setB(B*t,int a,int b){t->a=a;t->b=b;}` (7c STM+74 STRD) +
plain field stores; -O3 -Otime → 21/21 instructions, identical opcode ORDER,
delta is ONLY: 2-instruction swap at +c/+10 (add r1 ↔ mov r2) and a
4-register allocation permutation (5c-base r3↔ip, 7c-base r4↔r1, k ip↔r4,
flag-byte-1 r1↔ip). ~600 sweep variants (stmt order × locals × flags ×
constant forms) all land on this same plateau. Open: needs a source-level
use-order that makes armcc's allocator pick the target's permutation.
Helper-body physics ARE settled: tmp-copy body forces STM merge, plain body
splits; setP/setB need opposite body styles; volatile never merges;
aggregates const-pool; placement-new unavailable.

## armlib memfunc cluster — identified and disposed (2026-10-27)

The binary's C-library memory functions are ARM's hand-written runtime
asm, not compiled C, and are now `excluded_library`:

- `0x1164F4` = `__aeabi_memclr` (bzero core; +4 interior entry at
  0x1164F8 = the "fill with r2" memset-core ABI), 31 callers.
- `0x110490` = `__aeabi_memclr4` (big aligned zero loop; `mov lr,r2` then
  lr in the `stm` fill list — a compiler never clobbers lr mid-body), 87
  callers. Anchor: honest 001DF478's header names both.
- `0x1164A8` = the arm C library `memset` wrapper: byte-broadcast via
  `and/orr lsl`, then `push {r0,lr}; bl core(+4); pop {r0,pc}`. The
  push/pop idiom appears in exactly ONE function of the whole binary;
  armcc C never emits it — tried 12 construct variants (return dst /
  callee-result / void, local vs inline broadcast) x {-O3,-O2}±Otime,
  plus --cpu=ARM9TDMI/4T (library-build flags): always r4 or a tail
  call. Negative recipes neg-armlib-push-r0lr and neg-lr-bulk-data now
  hard-skip these shapes before any compile budget.

**The extern-call abstraction needs no plumbing for callers** — fn.py
check never compares call targets (relocated words match on opcode
class; out-of-function branches resolve at link time). Any declared
extern name works, even for bl into interior entries: honest 001DF478
calls __aeabi_memclr via a plain memset extern. Game callers of
0x1164A8 (001BBDFC, 0023EA70, 004AEA18, 00689144, all unmatched) can
match the same way: declare `extern void* memset(...)`, call it.
Earlier claim "interior callee -> no symbol -> can't link" was wrong.

## 003E60D4 recipe confirmation + generalization (2026-10-27)

`003E60D4` (mixed u32/u8/u16 zero-init, 44B) matched honestly with the
zero-loop-r2 recipe at -O2 -Otime: dead-eliminated `if (n) self->a = 0;`
keeps arg n live, zero pins in r2, and the struct needs `u8 pad[2]` after
the two u8 members so the u16s start at 0x10 (natural alignment put them
at 0xe -> 4 OP diffs). Struct-padding alignment is now a confirmed recipe
ingredient: when a strh lands at a non-halfword-multiple offset in the
target, the C struct has an explicit padding member.

Open (same family, still open): 00328938 (1->r1, 0->r2, 19 scalar
stores) and 003CBE60 (r3=0xff, ip=0, r1=2 interleaved) resist the
dead-guard recipe — the guard fires the zero-pin only with the right
guarded member/position. Sweep grid (guard slot x guarded member x
flags) is the next move.

## armlib memfunc plumbing — resolved, no linker plumbing needed (2026-10-27)

**Correction of a LESSONS-adjacent claim:** fn.py check NEVER compares
call targets. Relocated call/branch words match on opcode class only
(rel type 1/28/29), and out-of-function branches resolve at link time.
Any extern name links to any target address — including interior
entries like the memset core. No special plumbing is needed for callers
of the C-library memory functions; a plain
`extern "C" void* memset(void*, int, unsigned);` (or a custom extern
name) matches the call word. Game-code callers of the memfunc cores
(4 unmatched callers of the 001164A8 memset wrapper) can match this way
with zero plumbing.

**The runtime itself is NOT C (2026-10-27):**
- `0x001164F4` `__aeabi_memclr` (memset core fills from r2 via +4
  entry 0x1164F8) — armlib hand-written asm, 31 direct callers.
- `0x00110490` `__aeabi_memclr4` (87 callers): `mov lr,r2` then lr used
  as bulk fill data in the `stm` list — a compiler never clobbers lr
  mid-function. lr-as-bulk-data is an asm-only signature.
- `0x001164A8` arm C library `memset` wrapper: `push {r0,lr};
  bl core(+4); pop {r0,pc}` — this idiom occurs in exactly one function
  of the whole 25,986; armcc emits r4-save or a tail call in every
  construct variant tried (12 x flags x --cpu=7TDMI/ARM9TDMI/4T/
  MPCore, void/pointer return). Verdict: compiler-runtime asm,
  `excluded_library` for all three (names anchored by honest 001DF478:
  `__aeabi_memclr=0x1164F4, __aeabi_memclr4=0x110490`).
- Negative recipes added: neg-armlib-push-r0lr, neg-lr-bulk-data
  (predicates in synth.check_negative — the loop hard-skips them).
- Callers of these cores match with a plain extern declaration; call
  targets are never compared (relocated words match on opcode class).
- Scan findings: 13 unindexed functions use `mov lr,rX` — most are
  FALSE positives (pool loads `ldr lr,[pc,#..]` misread as data);
  the true bulk-fill user is 0x110490. Two functions are called at a
  +4 interior entry: 00104244 (real, linker-inlined tiny-call pattern)
  and 001164F4 (armlib).
- Remote scratchpad: use the repo (`logs/tmptest/`), not /tmp (Termux
  has none); rm scratch dirs when done.

## stm r0! zero-batch family (00115570/0011591C/0011593C/00115B14/00115B3C) — partial physics (2026-10-27)

Five unmatched functions (28-44B, 0x115xxx vec-new ctor zone, no callers,
no data refs — orphans) share the shape:
`mov r1,#0; mov r2,#0; mov r3,#0; stm r0!,{r1,r2,r3} ×N; [str/stm r0
without writeback]; bx lr`.

18 construct probes established:
- **WB batches reproduce ONLY as param-copy + advanced-pointer reuse**:
  `u32* f(void* self, u32 a, u32 b, u32 c){ u32* p=(u32*)self;
  *p++=a; *p++=b; *p++=c; ...; *p++=a; return p; }` at -O3 -Otime emits
  `stm r0!,{r1,r2,r3}` ×5 + `str r1,[r0],#4` + bx (7/10 words on
  00115B14; the ONLY construct producing WB batches).
- All-constant zero stores NEVER batch (armcc folds them to one
  register; scalar str chains) — regardless of *p++, p+=3, struct
  tmp-copy, local array, inline helper, loop (unrolls to scalar),
  -Ospace (loop, not unrolled), memset/__aeabi_memclr (tail calls),
  dead-guard, live-n ctor forms. Local reassignment `a=0` on params
  folds too. No honest match in the corpus contains 0xE8A0000E.
- The missing piece: what makes armcc keep THREE DISTINCT zero
  registers and batch them. `return p-1` explains the plain final str
  (r0 = last slot, no post-inc) — combined with the param-copy form
  that would be 10/10 except the three movs.
- Hypothesis (unproven): compiler-generated vec-new ctor artifacts,
  not C source; if the family is confirmed unproducible it becomes a
  negative recipe (like the VFP-WB family).

## 004E015C — struct copy from returned pointer + AREA-POOL reproduction (2026-10-27)

9/10 words (only a trailing 0x00000000 pool word missing). Two recipes:

1. **The function** (8 words, matched exactly):
   `push {r4,lr}; add r4,r0,#0x3dc; bl get; ldm r0,{r1,r2};
   ldr r0,[r0,#8]; str r0,[r4,#8]; stm r4,{r1,r2}; pop {r4,pc}`
   Source: callee RETURNS A POINTER; the 12-byte struct copy is
   `T12* dst = (T12*)((char*)self + 0x3dc); *dst = *get();`
   The dst pointer must be hoisted into a local BEFORE the call (armcc
   schedules `add r4,r0,#0x3dc` pre-call only then; a direct
   `*(T12*)(self+0x3dc) = *get();` computes the address after the copy).
   NOT sret: `T12 x = make()` armcc copies through a stack temp
   (sub sp/mov r0,sp), wrong shape.

2. **The unreferenced literal pool**: the target section continues with
   {0x0000042C, 0x00000000} — no loader inside the function. 0x42C is
   NOT a valid ARM immediate (11 significant bits, no rotation form) —
   it MUST come from a literal pool. Reproduced the 0x42C word by
   compiling a SIBLING function in the same TU WITHOUT --split_sections:
   `extern unsigned long long g() { return 1068; }` pools 1068's low
   word; the area pool lands after the last function (f), exactly where
   the target has it. (armcc materializes 1068ULL as mov r0,#0 +
   ldr r1,[pc,#pool].) With --split_sections the pool would be
   per-function and f (no constants) gets none — so this TU was
   compiled WITHOUT --split_sections, unlike its neighbors.
   OPEN: the trailing 0 word. Not any pooled constant (armcc never
   pools 0; denormals flush under fpmode=fast; ldrd pairs were not
   chosen for u64 1068 in any use tried: return, by-value arg, store).
   Hypothesis: 8-byte pool/section alignment padding emitted by the
   original TU's pool (armcc pads some pools to 8; the mechanism that
   triggers the pad is not identified).

Other physics this session (00115B14 stm-batch family, 18 probes):
WB stm batches reproduce ONLY via `*p++ = <distinct param values>` with
the advanced pointer returned (see the full write-up above). The
5-function zero-batch family (00115570..00115B3C) remains open.

## stm-batch family follow-ups (2026-10-27, session 2)

- 001164A8-wrappers in the 0x258xxx zone: `002589D8`'s mystery is
  its 3-word trailing pool (0x70A210/0x712468/0x711F50, data ptrs of
  the 0x258998 parent function, whose bne tail lands in 0x2589D8 —
  candidate is a FALSE START: the push/bl/pop block is 0x258998's
  bne-tail path, not a function). Disposition: interior_address
  candidate; refine can't express "no function here".
  Action: worklist should skip false starts (branch-target-only
  candidates with no bl/data refs). Recorded: 002589D8.

Follow-up (same day): the 0x42C pool word did NOT actually come from the
u64-1068 sibling's area pool in a reproducible way — with
--split_sections it disappears, without it the whole-TU pool lands after
the last function but the trailing 0x00000000 still won't reproduce
(tried: u64 return/arg/store, static const u64/double/float, ldrd
forcing). 9/10 stands: the 8-word function body is fully explained, the
trailing {0x42C, 0} pool block needs either the original TU's other
functions or an armcc pool-padding trigger that hasn't been identified.
The function body itself (8 words) is RESOLVED physics — see above.

## 003CBE60 (36B byte-field setter) — regalloc puzzle (2026-10-27)

Target: `mov r3,#0xff; strb r3,[r0,#2]; mov ip,#0; strb r3,[r0,#3];
str ip,[r0,#4]; mov r1,#2; strb ip,[r0]; strb r1,[r0,#1]; bx lr`.
~10 probes: locals-first-declaration, named locals (z/ff/two), guard
liveness (t+u), -O2/-O3. armcc always assigns 0xff→r1/r2/ip, never
r3-first / ip-second / r1-third as the target does. r3-first implies
params 1-2 live at the first computation; r1=2 implies param1 dead by
the third value — contradictory lifetime order under any single-pass
model. Likely needs a two-block structure (the zero/0xff stores in a
different basic block than the 2-store). PARKED.

2026-11-03 session, +6 probes: reversed source store order (b,a,e,d,c)
DOES flip the allocation to r3-first (r3=2, r1=0, r2=0xff) — proof the
reverse allocation exists — but the store schedule then follows program
order (b,a,e,d,c), not the target's address order (c,d,e,a,b). Explicit
value locals (ff,zero,two computed first) keep forward alloc (r1=0xff,
r2=0, r3=2). Volatile-sink liveness adds push/pop (wrong shape); dead
guards get DCE'd without shifting alloc. The target's (r3=0xff, ip=0,
r1=2) with address-order stores needs first-computed→r3 AND address-order
stores — no single-pass construct found. PARKED again.

## 001CD1D4 (44B) — parked after ~8 probes (2026-10-27)

Shape: `push {r4,lr}; mov r4,r0; bl sub(self+0x400, 0) [r1=0 hoisted
pre-push in TARGET, armcc rematerializes it post-push in every try];
mov r1,#1; strb r1,[r4,#0x425]; ldr r1,[pool=0x42C]; mov r0,#0;
strb r0,[r4,#0x426]; mov r0,#2; strh r0,[r1,r4] (register-offset store
— 0x42C exceeds strh's 255 imm); pop`.

Two constructs identified: (a) register-offset strh from the 0x42C
offset exceeding strh's 255 — pooled constant + [r1,r4] form; (b) r1
reuse chain 0→1→0x42C suggests the zero is a live arg reused as scratch.
3/13 after struct-layout fixes (b1 at 0x425, b2 at 0x426, v at 0x42c:
pad[0x425], b1, b2, pad2[5], v). Open: what keeps r1=0 live from
pre-call through the strh base (dead-guard + live-arg combos at -O2/-O3).

## 0059F7B8 (48B static-init) — 11/12, one unused pool word short (2026-10-27)

fam_sti KB source (Id64/Pair globals, `data = Id64().v` ctor-init)
reproduces 11/12 words exactly — the whole function body AND both data
pointers. Missing: the trailing `.word 0xFFFFFFFF` pool word, which NO
code in the binary loads (scanned all pc-relative loads: zero loaders).
It is the tail of the original TU's shared area pool — some sibling's
constant (a pooled -1) that armcc placed after this function's pool.
Same open problem class as 004E015C's trailing 0: area-pool tails of
the original TU leak into the last function's byte range. Not
reproducible from the function's own source; needs either the sibling
that used the constant (then the pool layout matches) or acceptance of
the 1-word delta. NOT a hack candidate — the function body is fully
correct; only dead pool bytes differ.

Sibling context: 0x59F7E8 (next function, also a static-init, also
unmatched) is likely the sibling that used the -1 — solving IT may
complete this one's pool. They should be attacked together.

## stm-batch family: 6/7 on 00115570 — one mystery left (2026-10-27)

`extern u32* f(void* self, u32 a, u32 b, u32 c) { u32* p = (u32*)self;
*p++ = a; *p++ = b; *p++ = c; ×3; return p - 1; }` at -O3 -Otime gives
**6/7** on 00115570: exact `stm r0!,{r1,r2,r3} ×2; stm r0,{r1,r2,r3}; bx`
— missing ONLY the three leading `mov r1/r2/r3,#0`.
- `return p - 1` is what makes the LAST stm non-writeback (r0 = last
  slot, no post-inc).
- The three movs = the params assigned 0 withOUT const-propagation.
  armcc const-props `a = 0` and kills the batching (b13). An opaque
  helper write (`clear(&a,3)`) spills everything to the stack (s2).
- Best hypothesis: the source passed 0s AND the body re-assigned them
  via a path armcc treats as opaque (or the movs come from an inlined
  ctor `T3()` whose temporary lived in r1-r3). Unresolved after ~20
  probes across the family.
- Interim value: 00115570 at 6/7, 00115B14 at 7/10 with the same
  construct family — one insight (what keeps 3 distinct zero registers
  alive) closes 5 functions.

## The trailing -1 pool word is SHARED by the static-init family (2026-10-27)

005A8AA0 (different TU, different globals) shows the IDENTICAL 11/12
pattern as 0059F7B8 with the same fam_sti source shape — the trailing
`.word 0xFFFFFFFF` appears in both. Only 2 unmatched static-inits carry
it (of ~440 in the family; the rest registered cleanly). No code in the
binary loads either word (full-text pc-relative scan: zero loaders).
Conclusion: an area-pool/data artifact at those two specific addresses
(sibling constant or init-table sentinel), not reproducible from the
function's own C source. Both stay at 11/12 (95.7%) — body fully
correct, one dead data word short. PARKED unless a de-compilation of
the neighboring data areas explains them.

## 0040E4BC (32B) — 7/8, bitfield-extract shape (2026-10-27)

Target: `add r1,r1,#1; mul r1,r1; asr r2,r1,#31; add r1,r1,r2,lsr#30;
lsl r1,#14; lsr r1,#16; strh r1,[r0,#0x14]`.
- add+asr+lsr30 = SIGNED div-by-4 (round-toward-zero) — x must be signed.
- lsl 14 + lsr 16 = extract bits [2,18) of the quotient = a 16-bit
  bitfield at bit offset 2 (armcc emits lsl/lsr pairs for bitfield
  extracts).
- My `(u16)((q << 14) >> 16)` merged the /4 into the shift (lsl 12) —
  algebraically equal, different code. The ORIGINAL kept them separate:
  the /4 result was materialized as a value (used twice? or a bitfield
  READ from a stored word). 7/8 with every formulation tried; the
  non-merging form needs the /4 result to be a bitfield READ of a
  stored value (no load appears in target — so likely a compiler
  bitfield-extract of the division result at bit offset 2, i.e. the
  original read `x` through a `struct { int pad:2; int v:16; }`
  view. PARKED at 7/8.

## vtable-chain ctor family: 0033A9E0 / 0035DFD0 / 001CCEB8 (2026-10-27)

Identical twins: `ldr r1,[pc]=vtable; push {r4,lr}; str r1,[r0],#0x320;
add r2,r1,#0x58; str r2,[r0],#0xec; add r3,r2,#0x64; str r3,[r0],#0x90;
bl func_004EE540; sub r0,r0,#0x400; pop {r4,lr}; sub r0,r0,#0x9c`.
C++ multiple/virtual-inheritance ctor: 4 vptr stores (bases at +0,
+0x320, +0x40C, +0x49C) with writeback pointer advances by base strides,
then a helper call (004EE540), then a this-adjustment return (r0 =
adjusted this — deleting-dtor family). Needs reconstructed base-class
layouts. PARKED until the base-class headers are recovered.

## 00499094 (28B) — the no-CSE reload pattern (2026-11-02)

Target: `ldr r2,&vtab; ldr r3,[r2]; str r3,[r0,#0x14]; ldr r3,[r2];
str r3,[r0,#0x18]; ldr r2,[r2]; str r2,[r0,#0x1c]; ldr r2,[pc]=6A8B40;
ldr r2,[r2]; str r2,[r0,#0x20]` — the vtable VALUE is reloaded before
every store (no CSE), base pointer r2 loaded once, r1 skipped.
- The reloads = the stores may alias the source: requires self and the
  vtable symbol to be the SAME pointer type (u32*) — verified (n6/n7).
- armcc STILL CSE'd when the base was a local copy of the array address;
  the no-CSE form needs the base to be a GLOBAL POINTER VARIABLE
  dereferenced per use (`extern u32* g; self[5] = *g;` — n7: reloads
  appear but with an extra indirection level).
- r1 skipped = param1's home occupied at allocation time; a dead u32
  param got reused (n8), so param1 must be live-opaque. PARKED at 23%.

## 002BDD6C (56B) — 9/14, flag-RMW + conditional tail (2026-11-02)

`self->0x59c |= 0x2000; r = f2(self); if (!r) return 0;
 return f3(self, (short)self->0x2e, r);` — best form uses a `u32* flags`
pointer for the RMW (writeback ldr/str) + locals for v/r: 9/14. The
target reads the flag via r0 (param, pre-r4) and writes via r4; the tail
call happens AFTER `pop {r4,lr}` with `mov r0,r2` — armcc in my compiles
either wrote back differently or moved the return value early. The C is
semantically right; the schedule isn't. PARKED.

## 002FF488 (56B) — memclr4 ctor, hoist nuance (2026-11-02)

`push {r4,lr}; mov r1,#0x6c; bl __aeabi_memclr4; mvn r2,#0;
str r2,[r4,#0x30..0x38,0x3c]; mov r0,#0; str r0,[r4,#0x6c];
strb r0,[r4,#0x29]; mov r0,r4` — ctor: memclr 0x6c bytes, -1 fields at
0x30-0x3c, zero at 0x6c/0x29, return self. The memfunc extern pattern
works (bl resolves). Target hoists `mvn r2,#0` ABOVE the push (first
instruction); my compiles schedule it after (and push r5/r6 extra when
the -1 is a live local). 6/14. The hoist-above-prologue nuance isn't
controlled by any construct tried. PARKED.

## 002FF488 (56B) — memclr4 ctor, hoist nuance (2026-11-02)

`push {r4,lr}; mov r1,#0x6c; bl __aeabi_memclr4; mvn r2,#0;
str r2,[r4,#0x30..0x38,0x3c]; mov r0,#0; str r0,[r4,#0x6c];
strb r0,[r4,#0x29]; mov r0,r4` — ctor: memclr 0x6c bytes, -1 fields at
0x30-0x3c, zero at 0x6c/0x29, return self. The memfunc extern pattern
works (bl resolves). Target hoists `mvn r2,#0` ABOVE the push (first
instruction); my compiles schedule it after (and push r5/r6 extra when
the -1 is a live local). 6/14. The hoist-above-prologue nuance isn't
controlled by any construct tried. PARKED.

## 003F6FBC (56B) — 69%: scattered stores + tail WB/stm (2026-11-02)

`mov r2,#0; str r2,[r0,#0x460/470/478/4e0/464/468/46c/47c];
str r2,[r0,#0x480]!; add r0,r0,#8; mov r3,r2; stm r0,{r2,r3}`.
With `(self, x, y=0-from-caller)`: all 9 scattered stores match (r2 = y's
home). The tail (WB str + add + stm) needs p to be a RUNNING pointer
folded into the 0x480 store — but the scattered p[i] stores anchor p at
base so armcc computes p += 0x121/0x122 separately (str [0x484] or
[0x488], no WB, no stm). The original likely used a second running
pointer for the tail region. PARKED at 69%.

## 0059F8A4 (28B) — armcc arg-evaluation-order puzzle (2026-11-02)

`ldr r0,&arr; ldr r1,&ctor; mov r3,#0x14; mov r2,#8; push {r4,lr};
blx __aeabi_vec_ctor_nocookie; mov r1,#0; add r3,r0,#0xa0; mov r2,r1;
stm r3,{r1,r2}; str r1,[r0,#0xa8]` — vec-ctor-nocookie for a bss array
(8 B x 0x14) + 3 zero stores at +0xa0/a4/a8.
- The body AFTER the call matches with the KB pattern, but armcc loads
  the two pc-relative CONSTANT args SWAPPED (ctor→r0, arr→r1) in every
  decl form tried (extern "C", C++ mangled, ptr-global, struct member,
  local copy). The matched KB sibling (002335B8) had arg1 = p->items (a
  MEMORY load) and got (arr, ctor) — armcc's evaluation order differs
  for pc-relative constants vs memory loads. The target wants arr
  (constant) loaded FIRST. PARKED at 8/14 — needs the construct that
  makes armcc evaluate a constant arg first (or the real bss symbol
  type).

## 001511F0 (36B flag+tail-call) — schedule-order wall (2026-11-03)

Target: `mov r2,r0; ldr r0,[r0] (m0); mov r3,#1; add r1,r0,#0x14;
ldr r0,[r2,#0x1c] (m1c); add r2,r2,#0x10; strb r3,[r0,#0xa0];
add r0,r0,#0x94; b func_00115C8C` — self->m1c->flagA0=1; tail call
(m1c+0x94, m0+0x14, self+0x10). ~7 probes: inline args, local caches,
comma-operator-in-arg2/arg3, self-copy local, by-value Vec3 arg3,
-Ospace. armcc always loads m1c FIRST (flag store scheduled before
the m0 load); target loads m0 first and m1c once, after. No source
dependency forces the order (flag base is self-relative, not
m0-derived). Self-copy mov r2,r0 appears only with a self local.
PARKED — schedule-order wall.

## VFP elementwise-op family (00115C54/C70/D54/DAC/C8C) — fresh-reg wall (2026-11-03)

Target shape (add/sub/mul/div): `vldmia r1,{s0-s2}; vldmia
r2,{s3-s5}; vop s6,s0,s3; vop s7,s1,s4; vop s8,s2,s5; vstmia
r0,{s6-s8}` — products into FRESH regs s6-s8, x,y,z order. All
constructs tried (locals-first, pointer-walk, array, struct-copy,
free operator*, by-value args, reversed operand order, -Ospace)
give in-place reuse (s0,s2,s1, scrambled) or scalar vldr/vstr.
armcc reuses a dead input's reg for the result; the target's
compiler allocated fresh. 00115DAC (vmla: dst[i]=v[i]*k+w[i], k
in VFP arg s0) — target batches BOTH loads and accumulates
in-place into w's regs s4-s6; every construct gives v batched
into s4-s6 and w degraded to scalar vldr. The VFP allocator's
batch-vs-scalar + fresh-vs-inplace choice is source-insensitive
here. PARKED — needs a new lever (maybe the original used a
Vec3 class with specific member layout or an inline method the
scheduler treats atomically).

## 002C3098 (28B rec-fill) — sub-object-pointer fold wall (2026-11-03)

Target: `add ip,r1,#0x24; mov r1,#0; strb r1,[ip,#4]; ldr
r0,[r0,#0x1c]; str r0,[ip]; strd r2,r3,[ip,#8]; bx` — the
sub-object base (dst+0x24) is materialized in ip and all 4 stores
go through it. Every construct (p local, inlined helper taking
Rec*, sub-struct Pair, local Rec + struct assign, -Ospace) gets
the base FOLDED into each store (str [r1,#0x24] etc.) because the
offsets fit the encodings — armcc rematerializes for free. The
target's ip retention is unexplained (maybe a member function of
a different class or an opaque derivation). Same fold-wall family
as 0040E390's r0-reservation. PARKED.

## 00115B3C (44B identity-matrix init) — initializer-streaming wall (2026-11-03)

Target: `mov r1,#0x3f800000; mov r2,#0; mov r3,#0; stm r0!,{r1,r2,r3};
stm r0!,{r2,r3}` x3 + `str r1,[r0]` — identity matrix (16 words,
w0/w5/w10/w15 = 1.0f bit pattern) streamed through core regs with
the runs (r1,r2,r3),(r2,r3) repeating. Probes: float initializer
(rodata copy), float direct (VFP vstr), u32 direct (r1=0! zero
hoisted first, stm {r1,r2} pairs), value locals, chained assigns,
running pointer, u64 pairing. armcc always hoists the zero constant
to r1 and batches only pairs; the target's 1.0f-in-r1 + 3-wide stm
streams = the compiler's initializer streaming with 1.0f computed
first — no source construct found. Related: the VFP elementwise
family (00115C54/C70/D54/DAC) — target allocates products to FRESH
regs (s6-s8) in x,y,z order; every construct gives in-place reuse
(s0,s2,s1 scrambled) or scalar vldr/vstr. 00115DAC (vmla family,
k in VFP arg s0): target batches BOTH loads (v→s1-s3, w→s4-s6) and
accumulates in-place into w; constructs give v batched high + w
scalar scrambled. PARKED — VFP allocator + initializer streaming
wall.

## 0041BD4C (44B u16 fill 0xffff) — loop-reversal wall (2026-11-03)

Target: `ldr r2,=bss; mov r0,#0; mvn r1,#0; L: add r3,r2,r0,lsl#1;
add r0,r0,#2; strh r1,[r3]; strh r1,[r3,#2]; cmp r0,#0x10; blt L`
— count-up index loop (i step 2), pair strh, SIGNED blt, value
0xffffffff in the register (mvn, no pool). Best: do-while + u32 i +
`(int)i < 0x10` compare = 9/11 (90.9%) — only delta: armcc schedules
the cmp BETWEEN the two strh. Probes: u32 step-2 for-loop (reversed
to countdown pointer-walk), u16 index (uxth), -1/0xffff/~0/u32 v
(all truncate to 0xffff pool — only s16 array + -1 keeps mvn),
inlined put16 helper, global index, volatile base. The mvn-vs-pool
choice: s16 array + -1 keeps mvn; u16 array truncates to 0xffff
pool. The count-up vs countdown: armcc reverses unless blocked;
volatile changes the counter shape but not to the target's. PARKED.

## 005A8148 (44B struct reset) — zero-hoist vs strd wall (2026-11-03)

Target: `ldr r2,=g; mvn r0,#0; mov r1,r0; mov r3,#0; strd
r0,r1,[r2,#8]; add r0,r2,#0x10; str r3,[r0]; str r3,[r0,#4]; str
r3,[r2]` — g->bc(u64)=-1 strd first, then de=0, a=0. Found: bc is
a u64 field ((u64)-1 → mvn+copy+strd — the copy exists because
strd needs two regs). Remaining delta: my compiles hoist the zero
stores ABOVE the strd (scheduler); target keeps strd first. No
source dependency blocks the hoist (all addresses/values constant).
PARKED.

## 0041BD4C (44B u16 fill 0xffff) — addendum (2026-11-03)

do-while + s16 array + -1 gets mvn r0,#0 (no pool!) — 6/12 best.
The remaining deltas (countdown pointer-walk vs count-up index loop)
persist across: u16 index (uxth), != bound, u32 v variable, ~0,
inlined put16 helper, global index, volatile base, short array.
armcc's loop reversal + strength reduction is unstoppable for this
shape; the target's count-up index form suggests the original
source had something structurally different (possibly the loop
variable used after the loop, or a different inlining context).
PARKED.

## 001CD1D4 (48B call + flags + far u16 store) — scheduler-eager wall (2026-11-03)

Target: push; r4=self; bl 0037D414; mov r1,#1; strb r1,[r4,#0x425];
ldr r1,=0x42c; mov r0,#0; strb r0,[r4,#0x426]; mov r0,#2; strh
r0,[r1,r4] — the 0x42c offset (strh immediate max 255) forces the
pool load, scheduled LAZILY (between the stores). My compiles hoist
ALL constants first (r3=0x42c, r2=1, r0=0, r1=2, then stores).
Structure right (5/12): u8 at 0x425, u8 at 0x426, u16 at 0x42c.
The lazy-vs-eager constant scheduling didn't respond to -Ospace or
statement reordering. Same scheduler-eager family as 001511F0.
PARKED.

## 00487F04 (48B call + u16 bit set/clear) — writeback-miss wall (2026-11-03)

Target: push; ldr r1,[r0,#0x14]; mov r4,r0; bl func_004B96A0(r0=self,
r1=p14 — TWO-ARG call!); ldr r0,[r4,#0x14]; ldrh r1,[r0,#0x16]!
(writeback); orr #1; strh [r0]; ldr r0,[r4,#0x14]; bic #2; strh
[r0,#0x16]. KEY FINDING: func_004B96A0 takes (self, p14) — the p14
load into r1 is a second argument, not the call's arg0. With that,
10/12 (83.3%): only delta = the writeback on the first ldrh (target
keeps p+0x16 in r0 across the store; mine keeps p and uses [r0,
#0x16] twice). Reference, pointer-advance, local-p, direct forms
all refuse the writeback. PARKED — one scheduler delta short.

## 0059F7B8 (48B two-global reset) — same strd/zero-hoist wall (2026-11-03)

Target: `ldr r2,=g1(0x716618); mvn r0,#0; mov r1,r0; strd r0,r1,[r2];
ldr r0,=g2(0x716620); mov r1,#0; mov r2,r1; stm r0,{r1,r2}` — u64
g1 = -1 (strd), then u32 pair g2 = 0,0 (stm), with the g2 address
RELOADED (separate pool entry — two globals, not one struct; the
compiler reloads between accesses to different externs). Probes:
single struct (no reload, no strd), separate globals (reload yes,
but u64 → stm not strd, registers scrambled), cast-view u64 store,
u64 value local, padded layout (strd appeared but zeros hoisted
above it — the 005A8148 wall), inlined helper. Same strd/zero-hoist
wall family. PARKED.

## 001512B4 (52B Vec3 add + child store + flag) — dead-arg-reg reuse wall (2026-11-03)

Target: `push {r4,lr}; ldr r4,[r0,#0x1c]; sub sp,#0x10; add
r2,r0,#4; mov r0,sp; bl 00115C54(out=sp, a=v /*r1 passthrough*/,
b=self+4); ldm sp,{r0,r1,r3}; add r2,r4,#0x88; stm r2,{r0,r1,r3};
mov r0,#1; strb r0,[r4,#0xa0]` — c=m1c loaded FIRST (r4), self
discarded; ONE m1c use (no reload — the source uses a C* local!).
Shape twin of matched 001512E8 (same structure, different call-arg
registers: there r1/r2 = computed addresses; here r1 = the v
passthrough param). Best: direct setAdd + c local = 9/13 — delta:
the ldm list {r0,r1,r3} (target, skipping r2 = the stm base) vs
{r1,r2,r3} (mine) and the stm base r2 (target, reusing the dead
arg reg) vs ip (mine). The dead-arg-reg reuse (compiler treats arg
registers as free after the call) didn't fire in my compile with a
PASSTHROUGH param (r1 = v) — the twin's COMPUTED address args
(add-based) may enable it. Swapped setAdd args (commutative) =
worse (3/14). PARKED.

## 00182E1C (52B state-dependent tail call) — load-order + ternary wall (2026-11-03)

Target: `ldr r1,=G; ldr r1,[r1]; ldrb r2,[r1,#0x70]; ldr r1,[r0]
(obj); cmp r2,#4; mvn r2,#0 (dead — ternary else-base artifact);
ldr r3,[r1,#0xac]; beq; mov r1,#0; bx r3; mov r1,#4` — if/else with
DUPLICATED tail calls via a function pointer (o->fAC(o, state==4 ?
4 : 0)). Best: if/else duplicated-tail-call form = 5/13. Deltas:
(1) the scheduler hoists my obj load above the holder-deref chain
(target keeps the chain first); (2) the mvn r2,#0 dead value (the
compiler's ternary else-base artifact, not reproduced). Ternary
form gives conditional mov (movne) + single bx — wrong shape.
PARKED.

## 001CCEB8 (52B D1 dtor, 3-vtable) — vt-register swap + tertiary-offset (2026-11-03)

Twin of 00143074 (1.00 DNA). Structure identical: Primary(19
virtuals, pad 0x31c) + Secondary + Tertiary + Member_004EE540;
vt 006E021C; str writeback 0x320; secondary patch +0x58/+0xec;
tertiary +0x64/+0x90; member dtor 004EE540; sub 0x400+0x9c; tail
001510A4. Deltas: (1) the vt load register: target r1, mine r2
(the first two values' registers swapped — same anomaly as
005F689C); (2) the tertiary's offset: target +0x64 (25 slots),
mine +0x68 (26) — the Secondary's vtable = 3 entries (target) vs
4 (mine, D0 included). Probes: Secondary dtor-only (4 entries),
protected/private dtor (no effect), Primary +p18 (secondary
offset moved to 0x5c — Primary vtable = 2+20+1(D0) = 23 = 0x5c).
Vtable accounting: entries = 2 + virtuals + 1 (D0) for polymorphic
classes. For tertiary at 0x64: Secondary = 3 entries (no D0) —
no construct found. PARKED.

## 00368C3C (52B per-element flag set loop) — ldrd/kill-r0 wall (2026-11-03)

Target: `ldr r2,[r0,#0xa4] (count); ldr r0,[r0,#0xa8] (elems,
OVERWRITING self); mov r3,#0; L: add ip,r3,r3,lsl#3; add ip,ip,
r3,lsl#5 (=i*41); add r3,#1; add ip,r0,ip,lsl#3 (=elems+i*328);
cmp r3,r2; strb r1,[ip,#0x145]; bne L` — 1x loop, index
addressing with the mul decomposed (41*8), self KILLED by the
elems load. Probes: -O3 (2x-unrolled with odd-peel epilogue),
-O2 (ldrd pair load — self kept, the 00111EF0 wall), -Ospace
(push+writeback). The 1x + no-reduction + kill-r0 form not
reproduced. Element = 0x148 bytes, flag byte at +0x145. PARKED —
same ldrd/kill-r0 family as 00111EF0.

## 003752C4 (52B fields + conditional tail call) — eager-hoist wall (2026-11-03)

Target: `mov r3,#1; str r1,[r0,#0x494]; mov r2,#0; strb r3,
[r0,#0x4a1]; strb r2,[r0,#0x4a2]; ldr r3,[r0,#0x450]; mov r2,#1;
cmp r3,#0; strbne r2,[r3,#0x61]; cmp r1,#0; bne ret; b 00375314`
— strict source order: x494=arg; b4a1=1; b4a2=0; if(x450)
x450->b61=1; if(arg==0) tail-call 00375314. My compile (same
source!) hoists the x450 load + all constants ABOVE the stores
(0/13 but 64% similarity — same instruction set, reordered).
The eager-hoist scheduler anomaly (001CD1D4 family) — the target's
compiler kept strict source order. PARKED.

## 003CD95C (52B conditional bit-clear) — keep-r0 anomaly (2026-11-03)

Target: `ldr r1,[r0] (idx→r1, self KEPT dead in r0); cmp r1,#0x10;
ldr r2,=flags; ldrh r3,[r2]; lsr ip,r3,r1; tst ip,#1; beq; mov
ip,#1; bic r1,r3,ip,lsl r1; strh r1,[r2]` — the shift-DOWN test
((flags>>i)&1) + the bic clear. Instruction set reproduced (5/13)
but the register assignment shifted by one: mine idx→r0 (self
killed), flags→r1; target idx→r1 (self KEPT dead in r0), flags→r3.
The keep-r0 anomaly (inverted kill-r0, 00368C3C family). Dead
second param doesn't change it. The test form: (flags>>i)&1 (shift
down) + bic with (1<<i) as ip<<i — reproduced. PARKED.

## 003D5684 (52B init + call + flag + -1 pair) — -1 CSE/stm-merge wall (2026-11-03)

Target: `mvn r2,#0 (pre-push!); push {r4,lr}; stm r0,{r1,r2}
(x0=arg, x4=-1); add r0,#0xc; bl 003D4CD4(self+0xc, arg); sub
r0,#0xc; mov r3,#1; strb r3,[r0,#0x30]; mvn r1,#0 (RECOMPUTED —
no CSE across the call!); add r3,r0,#0x38; mov r2,r1 (COPY);
stm r3,{r1,r2} (x38/x3c = -1,-1 via stm with two regs)`.
Mine: push {r4,r5,r6} (the -1 KEPT in r5 across the call — CSE'd!),
scalar str r5 twice (no stm — one reg). Deltas: (1) the -1 CSE
across the call (mine CSEs + pushes r5; the target recomputes and
avoids the push); (2) the stm merge needs the value in TWO regs
(the copy) — mine has one. The inlined-helper and -Ospace forms
don't flip either. Same family as 005A8148/0059F7B8. PARKED.
