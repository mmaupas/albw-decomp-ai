typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1196]; S(void*); };
S* func_00608B48(void* value) { return new S(value); }
