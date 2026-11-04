typedef unsigned int u32;
struct Inner00291EB8;
struct Inner00291EB8 { void g(); };
struct Outer00291EB8 { char pad[0x14]; Inner00291EB8* m14; };
void func_00291EB8(Outer00291EB8* p) { p->m14->g(); }
