typedef unsigned int u32;
struct Inner002925A0;
struct Inner002925A0 { void g(); };
struct Outer002925A0 { char pad[0x14]; Inner002925A0* m14; };
void func_002925A0(Outer002925A0* p) { p->m14->g(); }
