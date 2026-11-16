typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2444]; S(void*); };
S* func_006040D0(void* value) { return new S(value); }
