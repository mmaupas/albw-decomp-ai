typedef unsigned int u32;
struct Inner002919E8;
struct Inner002919E8 { void g(); };
struct Outer002919E8 { char pad[0x14]; Inner002919E8* m14; };
void func_002919E8(Outer002919E8* p) { p->m14->g(); }
