typedef unsigned int u32;
extern "C" void f(void* self, u32 a, u32 b, u32 c) {
    u32* p = (u32*)((char*)self + 0x1fc);
    *p = a; p[1] = b; p[2] = c;
}
