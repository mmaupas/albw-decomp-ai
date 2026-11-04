typedef unsigned int u32;
struct Inner0028F7E4;
struct Inner0028F7E4 { void g(); };
struct Outer0028F7E4 { char pad[0x14]; Inner0028F7E4* m14; };
void func_0028F7E4(Outer0028F7E4* p) { p->m14->g(); }
