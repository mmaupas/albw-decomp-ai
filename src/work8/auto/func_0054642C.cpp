typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef signed char s8;
typedef short s16;
typedef int s32;
struct TypeInfo { const void* vt; };
extern "C" u32 data_00726808;
extern "C" TypeInfo data_0072680C;
extern "C" const char ro_006F5D08[];
extern "C" int __cxa_guard_acquire(u32* g);
extern "C" void __cxa_guard_release(u32* g);

static const TypeInfo* getTI()
{
    if (!(data_00726808 & 1) && __cxa_guard_acquire(&data_00726808)) {
        { TypeInfo* t = &data_0072680C; t->vt = ro_006F5D08; }
        __cxa_guard_release(&data_00726808);
    }
    return &data_0072680C;
}
static bool isTI(const void* a)
{
    const TypeInfo* ti = getTI();
    return ti == a;
}
extern "C" u32 func_0054642C(u32 a0, const void* a1)
{
    return isTI(a1) ? 1u : 0u;
}
