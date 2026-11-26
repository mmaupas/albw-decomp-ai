typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1400]; S(void*); };
S* func_00604BE0(void* value) { return new S(value); }
