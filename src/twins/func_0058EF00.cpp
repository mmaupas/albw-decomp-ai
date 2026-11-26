typedef unsigned int u32; typedef unsigned char u8;
extern u8 ro_006F4138[];
extern "C" void func_0044191C(void*);
void func_0058EF00(void* self) {
    char* p = (char*)self;
    const void* vt = ro_006F4138;
    *(const void**)p = (const char*)vt + 172;
    p -= 0x38;
    *(const void**)p = vt;
    func_0044191C(p);
}
