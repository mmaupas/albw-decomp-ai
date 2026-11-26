typedef unsigned int u32;
struct Inner002901D0;
struct Inner002901D0 { void g(); };
struct Outer002901D0 { char pad[0x14]; Inner002901D0* m14; };
void func_002901D0(Outer002901D0* p) { p->m14->g(); }
