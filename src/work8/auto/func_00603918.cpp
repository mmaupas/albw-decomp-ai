typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2508]; S(void*); };
S* func_00603918(void* value) { return new S(value); }
