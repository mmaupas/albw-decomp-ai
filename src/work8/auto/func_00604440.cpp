typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1496]; S(void*); };
S* func_00604440(void* value) { return new S(value); }
