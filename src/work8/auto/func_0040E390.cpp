// 0x40E390: p->flag = 0; p->value = f * 10.0f;
typedef unsigned int u32;
typedef float f32;
struct S40 {
    unsigned char flag;
    f32 value;
};
extern "C" void target(S40* p, f32 f) {
    p->flag = 0;
    p->value = f * 10.0f;
}
