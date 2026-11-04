typedef unsigned int u32;
struct Inner00291C28;
struct Inner00291C28 { void g(); };
struct Outer00291C28 { char pad[0x14]; Inner00291C28* m14; };
void func_00291C28(Outer00291C28* p) { p->m14->g(); }
