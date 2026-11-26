typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1148]; S(void*); };
S* func_00603844(void* value) { return new S(value); }
