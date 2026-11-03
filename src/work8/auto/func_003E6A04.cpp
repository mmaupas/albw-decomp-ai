// 0x3E6A04: memcpy into ring buffer at base+pos, advance pos.
typedef unsigned int u32;
struct Stream { char* base; u32 pos; };
extern "C" void func_001163A0(void* dst, const void* src, u32 n);
extern "C" void target(Stream* s, const void* src, u32 n) {
    func_001163A0(s->base + s->pos, src, n);
    s->pos += n;
}
