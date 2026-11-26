typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2452]; S(void*); };
S* func_0060517C(void* value) { return new S(value); }
