typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_002BC00C(void*, u32);
extern u8 ro_006C86EC[];
void* func_00603180(u32 a0) {
    void* p = func_0010BAB4(0x00000914);
    if (!p) return 0;
    void* r = func_002BC00C(p, a0);
    const void* vt = ro_006C86EC;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 132;
    return r;
}
