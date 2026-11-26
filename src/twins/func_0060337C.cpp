typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1200]; S(void*); };
S* func_0060337C(void* value) { return new S(value); }
