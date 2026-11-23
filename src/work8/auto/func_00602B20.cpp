typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00137F88(void*, u32);
extern u8 ro_006C6A8C[];
void* func_00602B20(u32 a0) {
    void* p = func_0010BAB4(1104);
    if (!p) return 0;
    void* r = func_00137F88(p, a0);
    const void* vt = ro_006C6A8C;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 84;
    return r;
}
