typedef unsigned int u32;
struct Inner001DBC94;
struct Inner001DBC94 { void g(); };
struct Outer001DBC94 { char pad[0x14]; Inner001DBC94* m14; };
void func_001DBC94(Outer001DBC94* p) { p->m14->g(); }
