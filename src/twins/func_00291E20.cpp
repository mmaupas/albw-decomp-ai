typedef unsigned int u32;
struct Inner00291E20;
struct Inner00291E20 { void g(); };
struct Outer00291E20 { char pad[0x14]; Inner00291E20* m14; };
void func_00291E20(Outer00291E20* p) { p->m14->g(); }
