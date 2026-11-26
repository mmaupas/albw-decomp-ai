typedef unsigned int u32; typedef unsigned char u8;
extern "C" void* func_0010BAB4(u32);
extern "C" void* func_002625C4(void*, u32);
extern u8 ro_006C5C94[];
void* func_0060286C(u32 a0) {
    void* p = func_0010BAB4(0x00000A0C);
    if (!p) return 0;
    void* r = func_002625C4(p, a0);
    const void* vt = ro_006C5C94;
    *(const void**)r = vt;
    *(const void**)((char*)r + 0x320) = (const char*)vt + 132;
    return r;
}
