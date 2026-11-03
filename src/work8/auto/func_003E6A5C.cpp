// 0x3E6A5C: n-1 hoisted to a local.
typedef unsigned char u8;
typedef unsigned int u32;
struct S { u32 x0; u32 x4; };
extern "C" void __aeabi_memclr(void* p, u32 n);
extern "C" void target(S* self, u32 n) {
    u32 cur = self->x4;
    u32 nm1 = n - 1;
    u32 aligned = (cur + nm1) & ~nm1;
    __aeabi_memclr((void*)(self->x0 + cur), aligned - cur);
    self->x4 = aligned;
}
