typedef unsigned int u32;
struct InnerA;
struct InnerA { void g(); };
struct OuterA { char pad[0x1c8]; InnerA* m; };
void func_00530844(OuterA* p) { p->m->g(); }
