typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[1156]; S(void*); };
S* func_006098C4(void* value) { return new S(value); }
