typedef unsigned int u32; typedef unsigned char u8;
struct Res560 { u32 v; u8 t; };
extern "C" bool func_005611C0(void*, Res560*);
bool func_00561184(void* a, u32* out) {
    Res560 r;
    if (!func_005611C0(a, &r)) return false;
    if (r.t != 0xD2) return false;
    *out = r.v;
    return true;
}
