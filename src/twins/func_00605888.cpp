typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_001AD594(void*, u32);
extern u8 ro_006D7134[];
void* func_00605888(u32 a0) {
    void* p = func_0010BAB4(0x000009C4);
    if (!p) return 0;
    void* r = func_001AD594(p, a0);
    const void* vt = ro_006D7134;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 132;
    return r;
}
