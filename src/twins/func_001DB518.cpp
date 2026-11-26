typedef unsigned int u32;
struct Inner001DB518;
struct Inner001DB518 { void g(); };
struct Outer001DB518 { char pad[0x14]; Inner001DB518* m14; };
void func_001DB518(Outer001DB518* p) { p->m14->g(); }
