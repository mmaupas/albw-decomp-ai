typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00381E94(void*, u32);
extern u8 ro_006E8274[];
void* func_00609F38(u32 a0) {
    void* p = func_0010BAB4(0x00000B5C);
    if (!p) return 0;
    void* r = func_00381E94(p, a0);
    const void* vt = ro_006E8274;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 132;
    return r;
}
