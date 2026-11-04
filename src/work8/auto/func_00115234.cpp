#include "../../shared/include/albw_types.h"

/* Twin of 00115224 with a separate second source pointer: 12 floats with
 * writeback on src (r1!), 4 floats from src2 (r2), 16 stored to dst (r0),
 * no writeback on the store. The 12-float load must keep its writeback even
 * though nothing reads past it: express it as p[12] load folded away by
 * reading through p AFTER incrementing, in a dead-but-present form. */
void func_00115234(f32* dst, const f32* src, const f32* src2) {
    const f32* p = src;
    f32 v[16];
    for (int i = 0; i < 12; i++) v[i] = p[i];
    p += 12;
    for (int i = 0; i < 4; i++) v[12 + i] = src2[i];
    for (int i = 0; i < 16; i++) dst[i] = v[i];
    (void)p;
}
