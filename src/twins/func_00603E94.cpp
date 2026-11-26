typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_001768A4(void*, u32);
extern u8 ro_006CFD24[];
void* func_00603E94(u32 a0) {
    void* p = func_0010BAB4(1360);
    if (!p) return 0;
    void* r = func_001768A4(p, a0);
    const void* vt = ro_006CFD24;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 144;
    return r;
}
