typedef unsigned int u32;
struct Inner00290240;
struct Inner00290240 { void g(); };
struct Outer00290240 { char pad[0x14]; Inner00290240* m14; };
void func_00290240(Outer00290240* p) { p->m14->g(); }
