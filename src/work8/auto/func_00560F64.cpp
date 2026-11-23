typedef unsigned int u32; typedef unsigned char u8;
struct Res560 { u32 v; u8 t; };
extern "C" bool func_00560FDC(void*, Res560*);
bool func_00560F64(void* a, u32* out) {
    Res560 r;
    if (!func_00560FDC(a, &r)) return false;
    if (r.t != 0xD2) return false;
    *out = r.v;
    return true;
}
