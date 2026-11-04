#include "../../work7/gpt15/range.h"
struct S1003DB7B8;
struct S1003DB7B8 { void g(); };
struct S0003DB7B8 { char pad[16]; S1003DB7B8* m10; };
struct S2003DB7B8 { char pad[4]; S0003DB7B8* m4; };
extern "C" void func_003DB7B8(S2003DB7B8* p) { p->m4->m10->g(); }
