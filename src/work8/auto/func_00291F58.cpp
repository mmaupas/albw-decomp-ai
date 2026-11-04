typedef unsigned int u32;
struct Inner00291F58;
struct Inner00291F58 { void g(); };
struct Outer00291F58 { char pad[0x14]; Inner00291F58* m14; };
void func_00291F58(Outer00291F58* p) { p->m14->g(); }
