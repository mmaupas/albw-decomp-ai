typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_0026463C(void*, u32);
extern u8 ro_006D2CD4[];
void* func_006048D0(u32 a0) {
    void* p = func_0010BAB4(0x00000A5C);
    if (!p) return 0;
    void* r = func_0026463C(p, a0);
    const void* vt = ro_006D2CD4;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 132;
    return r;
}
