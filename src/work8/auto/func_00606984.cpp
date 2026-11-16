typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2400]; S(void*); };
S* func_00606984(void* value) { return new S(value); }
