typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1152]; S(void*); };
S* func_00605488(void* value) { return new S(value); }
