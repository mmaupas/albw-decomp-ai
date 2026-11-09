// Recurring inlined class shapes mined from the 16k+ matched sources.
// Each shape below reproduced its bytes in many matched functions; the
// mined counts are in the commit message / logs. Include AFTER albw_types.h
// (or include albw_common.h which includes it). All shapes are C++-only —
// use .cpp sources when including this header.
//
// Verified: including this header and using albw::Id64 / albw::Pair
// reproduces func_005934D4 byte-exactly (RESULT: MATCH 11/11).
//
// Contents:
//   sead::SafeStringBase<T>          — vtable string wrapper (50 files)
//   albw::Id64 / albw::Pair          — s64 wrapper ctors (460/460 files)
//   albw::Word / albw::Counter       — wrapper ctors + conversion ops
//   albw::Flag16 / albw::Flag32      — bitflag setters (72/69 files)
//   albw::PtrCnt / PtrListBase / PtrList<N> — ptr-array ctor chain (439)
//   albw::CreateFn / albw::Factory   — factory storage shape (439)
//   albw::ListNode                   — doubly-linked node (9 files)
//   albw::Control2317                — u16 cur/max + param (70 files)
//   placement operator new           — inlined bare-mov form (9 files)

#ifndef ALBW_SHAPES_H
#define ALBW_SHAPES_H

#include "albw_types.h"

#ifndef ALBW_HAVE_S64
#define ALBW_HAVE_S64
typedef long long s64;
#endif

// sead SafeStringBase — the recurring vtable string wrapper (mined 50x).
// Placed in namespace sead to match sources that refer to sead::SafeString.
namespace sead {
template <class T>
struct SafeStringBase {
    virtual ~SafeStringBase() {}
    virtual void assureTerminationImpl_() const;
    const T* text;
    SafeStringBase(const T* s) : text(s) {}
};
typedef SafeStringBase<char> SafeString;
}  // namespace sead

namespace albw {

// s64 identifier with sentinel -1 (mined 460x)
struct Id64 {
    s64 v;
    Id64() : v(-1) {}
};

// s64 pair with zero init (mined 460x)
struct Pair {
    s64 v;
    Pair() : v(0) {}
};

// u32 word wrapper + conversion operators (mined: Word/operator int/u32/s32)
struct Word {
    u32 v;
    Word() {}
    Word(u32 x) : v(x) {}
    operator u32() const { return v; }
    operator s32() const { return (s32)v; }
};

// int counter wrapper (mined: "struct Counter { int v; Counter(int x) : v(x) {} }")
struct Counter {
    int v;
    Counter() {}
    Counter(int x) : v(x) {}
};

// 16-bit flag with self-assigning set/reset (mined 72x — the *this = Flag16(...)
// form is what produces the exact strh/ldrh pair, do NOT rewrite as v |= mask)
struct Flag16 {
    u16 v;
    Flag16() {}
    Flag16(u16 n) : v(n) {}
    void reset(u16 mask) { *this = Flag16((u16)(v & ~mask)); }
    void set(u16 mask) { *this = Flag16((u16)(v | mask)); }
};

// 32-bit flag with change/set/reset (mined 69x)
struct Flag32 {
    u32 v;
    void change(u32 mask, bool on) { if (on) v |= mask; else v &= ~mask; }
    void set(u32 mask) { change(mask, true); }
    void reset(u32 mask) { change(mask, false); }
    void change(u32 a, u32 b) { v = (v | a) & ~b; }
};

// ptr-count base + list with inline buffer (mined 439x chain)
struct PtrCnt {
    int num, max;
    PtrCnt(int n) : num(0), max(n) {}
};
struct PtrListBase : PtrCnt {
    void** ptr;
    PtrListBase(int n, void* b) : PtrCnt(n), ptr(0) { if (b) ptr = (void**)b; }
};
template <int N>
struct PtrList : PtrListBase {
    void* buffer[N];
    PtrList() : PtrListBase(N, buffer) {}
};

typedef void* (*CreateFn)();

// Factory storage blob (mined 439x — ctor/dtor declared, bodies out-of-line)
struct Factory {
    char storage[0x248];
    Factory(CreateFn, u32, const sead::SafeString&, PtrListBase*,
            const sead::SafeString&, const char*, int);
    ~Factory();
};

// Doubly-linked list node (mined 9x)
struct ListNode {
    ListNode* mPrev;
    ListNode* mNext;
    ListNode() : mPrev(0), mNext(0) {}
    void erase_();
    ListNode* next() const { return mNext; }
};

// Small control block (mined 70x)
struct Control2317 {
    u16 current, max;
    u32 pad4, param;
};

}  // namespace albw

// Placement operator new — armcc inlines this to a bare mov (mined 9x).
// Tagged nothrow forms (std::nothrow_t, NoThrow, func_0010BAB4) are declared
// per-source because each file uses its own tag struct; do not add them here.
inline void* operator new(unsigned int, void* p) throw() { return p; }


// ---------------------------------------------------------------------------
// Recurring free-helper bodies (mined verbatim across sources):
//   {func_00100B88();}                          x107  — global init tick
//   {if (p->m) p->m->g();}                      x104  — delegated go()
//   {return (u32)(((u64)func_00111A64(r) * n) >> 32);}  x52 — fast rand range
//   {return &g_00725974;}                       x45   — singleton accessor
//   {return p->m86c;}                           x51   — plain field getter
// These stay as macros/templates below because each source names its own
// struct types; the shapes (not the names) are what the header fixes.
// ---------------------------------------------------------------------------

// Fast random-in-range: multiply-high by a 64-bit PRNG step.
// Mined 52x as: return (u32)(((unsigned long long)func_00111A64(r) * n) >> 32);
extern "C" u64 func_00111A64(void* r);
namespace albw {
inline u32 randRange(void* r, u32 n) {
    return (u32)(((unsigned long long)func_00111A64(r) * n) >> 32);
}
}


// ---------------------------------------------------------------------------
// StateMgr family (mined 46x): state-machine manager with PMF enter/exec/exit
// arrays and an optional timeline. The execute() body is what reproduced bytes.
// ---------------------------------------------------------------------------
namespace albw {
struct SmOwner_; typedef void (SmOwner_::*SmFunc)();
struct SmTimeline { char pad[4]; };
extern "C" void func_00352210(void* timeline, bool b, float frame);
struct StateMgr {
    u32 mCounter; s8 mCur; s8 mNext; u8 mNum; u8 pad7[9];
    SmTimeline* mTimeline; SmOwner_* mOwner; SmFunc* mEnter; SmFunc* mExec; SmFunc* mExit;
    void execute() {
        StateMgr* s = this;
        (s->mOwner->*s->mExec[s->mCur])();
        u32 c = mCounter + 1; mCounter = c;
        if (mTimeline) func_00352210(mTimeline, true, (float)c);
    }
    void ChangeState(s8 state);
};
}  // namespace albw


// ---------------------------------------------------------------------------
// Callback-delegate shapes (mined 131x / 78x / 24x / 22x):
//   struct D { virtual bool invoke(void*); O* owner; bool (O::*fn)(void*); }
//   bool D::invoke(void* a) { if (owner && fn) return (owner->*fn)(a); return false; }
// The void/void* 2-arg variant is the same shape with (void*, void*).
// ---------------------------------------------------------------------------
namespace albw {
struct DelegateOwner {};
typedef bool (DelegateOwner::*DelegateFn)(void*);
struct Delegate {
    virtual bool invoke(void* a);
    DelegateOwner* owner;
    DelegateFn fn;
};
inline bool Delegate::invoke(void* a) {
    if (owner && fn) return (owner->*fn)(a);
    return false;
}
}  // namespace albw

#endif  // ALBW_SHAPES_H
