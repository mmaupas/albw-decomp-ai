// 0x004ECF84 — StateMgr exec (33 words), twin of honest 0013646C (MATCH 33/33).
// Same construct, StateMgr at owner+0x568; the trailing tail call targets the
// fall-through function 004ED008, which the original linker rewrote to NOP.
typedef unsigned int u32; typedef signed char s8; typedef unsigned char u8; typedef float f32;
struct Base { virtual void v(); };
typedef void (Base::*PMF)();
extern "C" void func_00352210(void*, u32, f32);
struct StateMgr {
    u32 mCount; s8 mCur; s8 mNext; u8 mNum; u8 pad7; u32 mNames[2]; void* mTimeline;
    Base* mOwner; PMF* mEnter; PMF* mExec; PMF* mExit;
    void exec() {
        (mOwner->*mExec[mCur])();
        u32 c = ++mCount;
        if (mTimeline) func_00352210(mTimeline, 1, (f32)c);
    }
};
struct Owner { u8 pad[0x568]; StateMgr mMgr; void func_0050FD14(); };
extern "C" void func_004ED008(Owner*);
void Owner::func_0050FD14() { mMgr.exec(); func_004ED008(this); }
