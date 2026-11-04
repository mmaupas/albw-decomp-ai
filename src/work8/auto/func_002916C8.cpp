typedef unsigned int u32;
struct Inner002916C8;
struct Inner002916C8 { void g(); };
struct Outer002916C8 { char pad[0x14]; Inner002916C8* m14; };
void func_002916C8(Outer002916C8* p) { p->m14->g(); }
