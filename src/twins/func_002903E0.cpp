typedef unsigned int u32;
struct Inner002903E0;
struct Inner002903E0 { void g(); };
struct Outer002903E0 { char pad[0x14]; Inner002903E0* m14; };
void func_002903E0(Outer002903E0* p) { p->m14->g(); }
