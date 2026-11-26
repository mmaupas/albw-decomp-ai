typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1384]; S(void*); };
S* func_00607810(void* value) { return new S(value); }
