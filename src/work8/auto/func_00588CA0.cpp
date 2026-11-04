typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef signed char s8;
typedef short s16;
typedef int s32;
struct TypeInfo { const void* vt; };
extern "C" u32 data_007278D8;
extern "C" TypeInfo data_007278DC;
extern "C" const char ro_006F5D08[];
extern "C" int __cxa_guard_acquire(u32* g);
extern "C" void __cxa_guard_release(u32* g);

static const TypeInfo* getTI()
{
    if (!(data_007278D8 & 1) && __cxa_guard_acquire(&data_007278D8)) {
        { TypeInfo* t = &data_007278DC; t->vt = ro_006F5D08; }
        __cxa_guard_release(&data_007278D8);
    }
    return &data_007278DC;
}
static bool isTI(const void* a)
{
    const TypeInfo* ti = getTI();
    return ti == a;
}
extern "C" u32 func_00588CA0(u32 a0, const void* a1)
{
    return isTI(a1) ? 1u : 0u;
}
