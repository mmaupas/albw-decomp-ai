typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1104]; S(void*); };
S* func_00608C5C(void* value) { return new S(value); }
