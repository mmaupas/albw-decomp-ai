typedef unsigned int u32;
static const u32 M1 = 0x55555555u;
static const u32 M2 = 0x33333333u;
static const u32 M4 = 0x0f0f0f0fu;
extern "C" u32 func_0048AC68(u32 x) {
    u32 r2 = M1 & (x >> 1);
    x = x - r2;
    r2 = M2 & x;
    u32 r0 = M2 & (x >> 2);
    x = r0 + r2;
    x = x + (x >> 4);
    x = x & M4;
    x = x + (x >> 8);
    x = x + (x >> 16);
    return x & 0x3f;
}
