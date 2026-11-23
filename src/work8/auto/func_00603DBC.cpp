typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1072]; S(void*); };
S* func_00603DBC(void* value) { return new S(value); }
