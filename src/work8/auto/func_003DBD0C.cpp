#include "../../work7/gpt15/range.h"
struct S1003DBD0C;
struct S1003DBD0C { void g(); };
struct S0003DBD0C { char pad[16]; S1003DBD0C* m10; };
struct S2003DBD0C { char pad[4]; S0003DBD0C* m4; };
extern "C" void func_003DBD0C(S2003DBD0C* p) { p->m4->m10->g(); }
