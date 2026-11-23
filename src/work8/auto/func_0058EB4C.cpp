typedef unsigned int u32; typedef unsigned char u8;
extern u8 ro_006F1758[];
extern "C" void func_004B9AA0(void*);
void func_0058EB4C(void* self) {
    char* p = (char*)self;
    const void* vt = ro_006F1758;
    *(const void**)p = (const char*)vt + 172;
    p -= 0x38;
    *(const void**)p = vt;
    func_004B9AA0(p);
}
