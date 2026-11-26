typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_0021E578(void*, u32);
extern u8 ro_006DAFA0[];
void* func_00606810(u32 a0) {
    void* p = func_0010BAB4(2608);
    if (!p) return 0;
    void* r = func_0021E578(p, a0);
    const void* vt = ro_006DAFA0;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 132;
    return r;
}
