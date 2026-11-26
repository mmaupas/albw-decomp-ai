typedef unsigned int u32;
struct Inner0028FBC8;
struct Inner0028FBC8 { void g(); };
struct Outer0028FBC8 { char pad[0x14]; Inner0028FBC8* m14; };
void func_0028FBC8(Outer0028FBC8* p) { p->m14->g(); }
