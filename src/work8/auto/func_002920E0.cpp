typedef unsigned int u32;
struct Inner002920E0;
struct Inner002920E0 { void g(); };
struct Outer002920E0 { char pad[0x14]; Inner002920E0* m14; };
void func_002920E0(Outer002920E0* p) { p->m14->g(); }
