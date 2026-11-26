typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2324]; S(void*); };
S* func_0060478C(void* value) { return new S(value); }
