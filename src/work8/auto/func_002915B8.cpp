typedef unsigned int u32;
struct Inner002915B8;
struct Inner002915B8 { void g(); };
struct Outer002915B8 { char pad[0x14]; Inner002915B8* m14; };
void func_002915B8(Outer002915B8* p) { p->m14->g(); }
