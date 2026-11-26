typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2700]; S(void*); };
S* func_00605530(void* value) { return new S(value); }
