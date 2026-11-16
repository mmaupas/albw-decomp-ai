typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_002E0DAC(void*, u32);
extern u8 ro_006DDC08[];
void* func_00607460(u32 a0) {
    void* p = func_0010BAB4(0x00000448);
    if (!p) return 0;
    void* r = func_002E0DAC(p, a0);
    const void* vt = ro_006DDC08;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 88;
    return r;
}
