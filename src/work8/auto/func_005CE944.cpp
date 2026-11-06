// 0x005CE944 — static initializer (60B), twin of honest 005CFE08 (MATCH 15/15).
// Twin emission: ldr r2=&T; strd -1,[r2,#8] (Id64 at T+8); ldr r0=&Pair; stm 0;
// sub r0,#0x10 (= &T); ldr/mov r1 = value; str r1,[r0] (T.m0); bx lr; 3 pool words.
// Only difference: m0 stores the ADDRESS of the object at 0x725970 (relocated
// word) instead of the twin's constant 0x10000000.
// NOTE: objects are non-static so the checker's relocation resolver sees named
// symbols (statics merge into anonymous .data section relocs, which fail the
// identity check).
typedef unsigned int u32; typedef long long s64;
struct Id64 { s64 v; Id64() : v(-1) {} };
struct Pair { s64 v; Pair() : v(0) {} };

extern char data_00725970;

s64 data_0070D828 = Id64().v;
Pair data_0070D830;
struct T_0070D820 { void* m0; T_0070D820() : m0(&data_00725970) {} };
T_0070D820 data_0070D820;
