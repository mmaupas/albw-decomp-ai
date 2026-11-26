typedef unsigned int u32;
struct Inner00440EF8;
struct Inner00440EF8 { void g(); };
struct Outer00440EF8 { char pad[0x14]; Inner00440EF8* m14; };
void func_00440EF8(Outer00440EF8* p) { p->m14->g(); }
