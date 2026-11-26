typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1576]; S(void*); };
S* func_006032A8(void* value) { return new S(value); }
