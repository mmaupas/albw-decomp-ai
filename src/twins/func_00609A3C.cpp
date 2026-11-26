typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1336]; S(void*); };
S* func_00609A3C(void* value) { return new S(value); }
