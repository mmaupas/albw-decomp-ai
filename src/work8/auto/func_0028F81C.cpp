typedef unsigned int u32;
struct Inner0028F81C;
struct Inner0028F81C { void g(); };
struct Outer0028F81C { char pad[0x14]; Inner0028F81C* m14; };
void func_0028F81C(Outer0028F81C* p) { p->m14->g(); }
