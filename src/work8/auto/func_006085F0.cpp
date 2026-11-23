typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00306CE0(void*, u32);
extern u8 ro_006E21A0[];
void* func_006085F0(u32 a0) {
    void* p = func_0010BAB4(0x000004CC);
    if (!p) return 0;
    void* r = func_00306CE0(p, a0);
    const void* vt = ro_006E21A0;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 84;
    return r;
}
