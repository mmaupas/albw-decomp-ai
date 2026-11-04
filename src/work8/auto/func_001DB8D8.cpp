typedef unsigned int u32;
struct Inner001DB8D8;
struct Inner001DB8D8 { void g(); };
struct Outer001DB8D8 { char pad[0x14]; Inner001DB8D8* m14; };
void func_001DB8D8(Outer001DB8D8* p) { p->m14->g(); }
