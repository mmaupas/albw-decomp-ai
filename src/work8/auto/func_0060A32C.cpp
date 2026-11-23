typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00338B24(void*, u32);
extern u8 ro_006E9CCC[];
void* func_0060A32C(u32 a0) {
    void* p = func_0010BAB4(0x000005BC);
    if (!p) return 0;
    void* r = func_00338B24(p, a0);
    const void* vt = ro_006E9CCC;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 84;
    return r;
}
