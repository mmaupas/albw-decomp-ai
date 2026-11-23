typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00301944(void*, u32);
extern u8 ro_006DE964[];
void* func_00607620(u32 a0) {
    void* p = func_0010BAB4(1600);
    if (!p) return 0;
    void* r = func_00301944(p, a0);
    const void* vt = ro_006DE964;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 120;
    return r;
}
