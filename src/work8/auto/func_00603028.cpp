typedef unsigned int u32;
void* operator new(u32) throw();
struct S { char pad[2356]; S(void*); };
S* func_00603028(void* value) { return new S(value); }
