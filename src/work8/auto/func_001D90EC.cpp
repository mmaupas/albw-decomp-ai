// 0x1D90EC: twin of 001D1B20 with the offsets 0x49c/0x40c.
typedef unsigned char u8; typedef signed char s8; typedef unsigned int u32; typedef int s32;
struct Packed5 { u8 a, b, g, r; };
struct Color4u8 {
    u8 r, g, b, a;
    Color4u8(u8 r_, u8 g_, u8 a_, u8 b_) : r(r_), g(g_), b(b_), a(a_) {}
    Color4u8(const Packed5& c) : r(c.r), g(c.g), b(c.b), a(c.a) {}
};
extern Packed5 data_0070F698;
struct MdlInfo { u32 m0; s32 m4; };
struct Mdl4F4 { char pad[0x20]; MdlInfo* m20; };
struct Act { char pad[0x40c]; Mdl4F4* m4f4; char pad2[0x49c - 0x410]; u8 m49c; };
void func_004CF5DC(Mdl4F4* m, s32 i, s32 k, const Color4u8* c);
extern "C" void target(Act* self, bool b) {
    self->m49c = b;
    Color4u8 white(0xff, 0xff, 0xff, 0xff);
    u8 R = data_0070F698.r, G = data_0070F698.g, B = data_0070F698.b, A = data_0070F698.a;
    Color4u8 base(R, G, A, B);
    const Color4u8* c = b ? &white : &base;
    Mdl4F4* m = self->m4f4;
    if (m) {
        for (s32 i = 0; i < m->m20->m4; i++)
            func_004CF5DC(m, i, 2, c);
    }
}
