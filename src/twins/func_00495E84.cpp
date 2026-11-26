// 0x495E84: virtual tail-call wrapper. r0 = self (passed straight through
// as the callee's this), r1 = passthrough arg, r2/r3 = pool-loaded consts
// as the 2nd/3rd explicit args. The vtable slot is 0x44/4 = 17 (17
// virtuals precede it). No devirtualization: the vtable is loaded from
// *self at runtime (the class has further-derived overrides).
typedef unsigned int u32;

struct V495 {
    virtual void v0();
    virtual void v1();
    virtual void v2();
    virtual void v3();
    virtual void v4();
    virtual void v5();
    virtual void v6();
    virtual void v7();
    virtual void v8();
    virtual void v9();
    virtual void v10();
    virtual void v11();
    virtual void v12();
    virtual void v13();
    virtual void v14();
    virtual void v15();
    virtual void v16();
    virtual void slot17(u32 a, u32 b, u32 c);   // vtable offset 0x44
};

extern u32 data_00714F38;
extern u32 bss_0079DFCC;

void target(V495* self, u32 x) {
    self->slot17(x, (u32)&data_00714F38, (u32)&bss_0079DFCC);
}
