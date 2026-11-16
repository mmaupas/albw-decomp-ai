typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00332D8C(void*, u32);
extern u8 ro_006D47F8[];
void* func_00604E20(u32 a0) {
    void* p = func_0010BAB4(0x0000051C);
    if (!p) return 0;
    void* r = func_00332D8C(p, a0);
    const void* vt = ro_006D47F8;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 92;
    return r;
}
