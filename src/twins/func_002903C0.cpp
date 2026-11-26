typedef unsigned int u32;
struct Inner002903C0;
struct Inner002903C0 { void g(); };
struct Outer002903C0 { char pad[0x14]; Inner002903C0* m14; };
void func_002903C0(Outer002903C0* p) { p->m14->g(); }
