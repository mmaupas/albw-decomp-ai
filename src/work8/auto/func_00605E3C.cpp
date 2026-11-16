typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00242ED4(void*, u32);
extern u8 ro_006D86A4[];
void* func_00605E3C(u32 a0) {
    void* p = func_0010BAB4(1136);
    if (!p) return 0;
    void* r = func_00242ED4(p, a0);
    const void* vt = ro_006D86A4;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 84;
    return r;
}
