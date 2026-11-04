typedef unsigned int u32;
struct Inner002924D0;
struct Inner002924D0 { void g(); };
struct Outer002924D0 { char pad[0x14]; Inner002924D0* m14; };
void func_002924D0(Outer002924D0* p) { p->m14->g(); }
