// 0x3DA464: fill buf[len .. len+n) with 0 (the count = n).
typedef unsigned char u8;
typedef unsigned int u32;
struct S { u32 buf; u32 x4; };
extern "C" void target(S* self, u32 arg, u32 n) {
    u32 len = (arg - self->x4) >> 4;
    u8* buf = (u8*)self->buf;
    for (u32 i = len; i < len + n; ++i)
        buf[i] = 0;
}
