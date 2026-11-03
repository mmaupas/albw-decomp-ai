// 0x40E4BC: p->m14 = (u16)((x+1)*(x+1) / 4);
typedef int s32;
typedef unsigned short u16;
struct S41 { char pad0[0x14]; u16 m14; };
extern "C" void target(S41* p, s32 x) {
    p->m14 = (u16)((x + 1) * (x + 1) / 4);
}
