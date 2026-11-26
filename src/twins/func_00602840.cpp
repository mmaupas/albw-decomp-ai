typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2324]; S(void*); };
S* func_00602840(void* value) { return new S(value); }
