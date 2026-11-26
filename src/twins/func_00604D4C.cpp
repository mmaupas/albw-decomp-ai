typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1208]; S(void*); };
S* func_00604D4C(void* value) { return new S(value); }
