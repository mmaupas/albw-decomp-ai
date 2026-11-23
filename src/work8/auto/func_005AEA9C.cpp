typedef unsigned int u32; typedef unsigned char u8;
extern u8 bss_007A8838[];
extern "C" void func_003C9E74(void*);
extern "C" void func_00100110(void*, void*, u32, u32);
void func_005AEA9C(void) {
    func_00100110(bss_007A8838, (void*)func_003C9E74, 0x10, 8);
}
