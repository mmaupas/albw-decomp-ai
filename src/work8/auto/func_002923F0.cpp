typedef unsigned int u32;
struct Inner002923F0;
struct Inner002923F0 { void g(); };
struct Outer002923F0 { char pad[0x14]; Inner002923F0* m14; };
void func_002923F0(Outer002923F0* p) { p->m14->g(); }
