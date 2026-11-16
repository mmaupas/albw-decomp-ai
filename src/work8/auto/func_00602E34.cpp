typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00189FC8(void*, u32);
extern u8 ro_006C73C0[];
void* func_00602E34(u32 a0) {
    void* p = func_0010BAB4(0x00000704);
    if (!p) return 0;
    void* r = func_00189FC8(p, a0);
    const void* vt = ro_006C73C0;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 120;
    return r;
}
