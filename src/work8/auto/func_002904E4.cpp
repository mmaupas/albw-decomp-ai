typedef unsigned int u32;
struct Inner002904E4;
struct Inner002904E4 { void g(); };
struct Outer002904E4 { char pad[0x14]; Inner002904E4* m14; };
void func_002904E4(Outer002904E4* p) { p->m14->g(); }
