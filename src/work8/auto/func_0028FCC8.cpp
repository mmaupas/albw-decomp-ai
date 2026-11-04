typedef unsigned int u32;
struct Inner0028FCC8;
struct Inner0028FCC8 { void g(); };
struct Outer0028FCC8 { char pad[0x14]; Inner0028FCC8* m14; };
void func_0028FCC8(Outer0028FCC8* p) { p->m14->g(); }
