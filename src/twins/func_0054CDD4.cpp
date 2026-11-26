// 0x54CDD4: same-TU definition of the query (IPRA!).
typedef unsigned int u32;
typedef signed char s8;
struct Owner { char pad[0x10C]; u32 mask; };
struct PlayerProxy { char pad[0x10]; char *player; Owner *owner; };
struct Global1 { char pad[0x23]; unsigned char m23; };
struct Global2 { char pad[0x44]; void *m44; };
extern "C" Global1 *data_00712468;
extern "C" Global2 *data_0070B728;

extern "C" __declspec(noinline) u32 func_0054CE64(PlayerProxy *p, int kind)
{
    char *s = p->player + 0x694;
    if (*(s8 *)(s + 0x11) == kind) return 0x10;
    if (*(s8 *)(s + 0x1D) == kind) return 8;
    return 0;
}

extern "C" bool target(PlayerProxy *p)
{
    u32 m = func_0054CE64(p, 11);
    if (m == 0) return false;
    if ((m & p->owner->mask) != 0) return false;
    if (data_00712468->m23 != 0) return false;
    return data_0070B728->m44 == 0;
}
