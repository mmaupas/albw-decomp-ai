// 0x005CBE9C — static initializer (60B), fam_sti family.
// Target emission: ldr r2=&owner; strd -1,[r2,#0x18] (owner.id);
// ldr r0=&pair; stm 0 (pair.v); sub r0,#0x20 (= &owner); strb 0,[r0];
// add r0,#1; strb 0,[r0] (owner.f0/f1 written via pointer arithmetic from
// &pair, so Pair's ctor must reference the owner through &pair-derived pointer).
typedef unsigned int u32; typedef long long s64; typedef unsigned char u8;

struct Owner {
    u8 f0; u8 f1; u8 pad[0x16]; s64 id;
};
Owner owner;

struct Pair { s64 v; };
Pair pair;

struct Init {
    s64 id_hold;
    Init() { owner.id = -1; }
};
struct FlagInit {
    FlagInit() {
        pair.v = 0;
        u8* p = (u8*)&pair - 0x20;
        p[0] = 0; p[1] = 0;
    }
};
Init init;
FlagInit flaginit;
