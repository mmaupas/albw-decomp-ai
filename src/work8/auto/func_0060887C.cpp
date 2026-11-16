typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2444]; S(void*); };
S* func_0060887C(void* value) { return new S(value); }
