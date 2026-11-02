typedef unsigned int u32;
struct Buf { u32 a, b, c; };
extern "C" void release(void* p);
extern "C" void f(Buf* self) {
    if (self->c) {
        release((void*)self->c);
        self->c = 0;
        self->a = 0;
        self->b = 0;
    }
}
