typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_00279840(void*, u32);
extern u8 ro_006DBD40[];
void* func_00606ADC(u32 a0) {
    void* p = func_0010BAB4(0x000004BC);
    if (!p) return 0;
    void* r = func_00279840(p, a0);
    const void* vt = ro_006DBD40;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 92;
    return r;
}
