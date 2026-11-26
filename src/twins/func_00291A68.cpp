typedef unsigned int u32;
struct Inner00291A68;
struct Inner00291A68 { void g(); };
struct Outer00291A68 { char pad[0x14]; Inner00291A68* m14; };
void func_00291A68(Outer00291A68* p) { p->m14->g(); }
