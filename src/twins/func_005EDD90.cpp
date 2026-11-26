typedef long long s64; typedef unsigned char u8; typedef float f32;
struct Id64 { s64 v; Id64() : v(-1) {} };
struct Pair { s64 v; Pair() : v(0) {} };
struct Owner { u8 pad[0x10]; s64 id; };
Owner data_00714EC8 = { {0}, Id64().v };
Pair data_00714EE0;
struct W { W() {
    f32 m = -3.40282346638528859811704183484516925440e+38F;
    char* p = (char*)&data_00714EE0 - 0x18;
    *(f32*)p = m; *(f32*)(p+4) = m;
    *(s64*)(p+8) = (s64)0x8000000080000000ULL;
} };
W w_00714EE8;
