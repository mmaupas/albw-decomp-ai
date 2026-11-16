typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2452]; S(void*); };
S* func_006035E8(void* value) { return new S(value); }
