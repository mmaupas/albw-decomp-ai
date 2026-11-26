typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_001D2BC4(void*, u32);
extern u8 ro_006C76E8[];
void* func_00602EEC(u32 a0) {
    void* p = func_0010BAB4(1600);
    if (!p) return 0;
    void* r = func_001D2BC4(p, a0);
    const void* vt = ro_006C76E8;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 120;
    return r;
}
