// 0x524898: union word/float views, +0.5f adjust (twin 0052BC58).
typedef unsigned int u32; typedef float f32;
struct Vec3 { f32 x, y, z; };
union V { Vec3 xyz; u32 words[3]; };
struct S { char pad[0x3d0]; V pos; };
extern "C" void target(S* p, V* out) {
    if (out) {
        out->words[0] = p->pos.words[0];
        f32 y = p->pos.xyz.y;
        out->words[1] = p->pos.words[1];
        out->words[2] = p->pos.words[2];
        out->xyz.y = y + 0.5f;
    }
}
