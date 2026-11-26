typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_0039C0F8(void*, u32);
extern u8 ro_006E7CB4[];
void* func_00609E38(u32 a0) {
    void* p = func_0010BAB4(0x0000098C);
    if (!p) return 0;
    void* r = func_0039C0F8(p, a0);
    const void* vt = ro_006E7CB4;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 188;
    return r;
}
