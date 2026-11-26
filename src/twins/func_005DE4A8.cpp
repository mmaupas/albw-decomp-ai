// 0x005DE4A8 — static initializer (64B), fam_sti, MATCH 16/16.
// Emission: ldr r2=&owner; strd -1,[r2,#8] (owner.id); vldr s0=FLT_MAX (pool);
// ldr r0=&pair; stm 0 (pair.v); sub r0,r0,#0x10 (= &owner, derived from &pair);
// vstr s0,[r0,#4]; vstr s0,[r0]. Owner.id is a dynamic aggregate member
// ({0, Id64().v}); the two FLT_MAX stores live in W's ctor through
// (char*)&pair - 0x10, reusing the live &pair register after the stm.
typedef long long s64; typedef float f32;
struct Id64 { s64 v; Id64() : v(-1) {} };
struct Pair { s64 v; Pair() : v(0) {} };
struct Owner { s64 a, id; };
Owner data_00709CC8 = { 0, Id64().v };
Pair data_00709CD8;
struct W { W() {
    f32 m = 3.40282346638528859811704183484516925440e+38F;
    char* o = (char*)&data_00709CD8 - 0x10;
    *(f32*)(o + 4) = m;
    *(f32*)o = m;
} };
W w_00709CE0;
