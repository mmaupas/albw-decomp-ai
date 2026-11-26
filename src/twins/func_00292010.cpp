typedef unsigned int u32;
struct Inner00292010;
struct Inner00292010 { void g(); };
struct Outer00292010 { char pad[0x14]; Inner00292010* m14; };
void func_00292010(Outer00292010* p) { p->m14->g(); }
