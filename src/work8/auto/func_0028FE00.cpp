typedef unsigned int u32;
struct Inner0028FE00;
struct Inner0028FE00 { void g(); };
struct Outer0028FE00 { char pad[0x14]; Inner0028FE00* m14; };
void func_0028FE00(Outer0028FE00* p) { p->m14->g(); }
