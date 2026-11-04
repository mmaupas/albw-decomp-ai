typedef unsigned int u32;
struct Inner0028FD00;
struct Inner0028FD00 { void g(); };
struct Outer0028FD00 { char pad[0x14]; Inner0028FD00* m14; };
void func_0028FD00(Outer0028FD00* p) { p->m14->g(); }
