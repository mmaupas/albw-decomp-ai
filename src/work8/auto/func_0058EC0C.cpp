typedef unsigned int u32; typedef unsigned char u8;
extern u8 ro_006F205C[];
extern "C" void func_004B9AA0(void*);
void func_0058EC0C(void* self) {
    char* p = (char*)self;
    const void* vt = ro_006F205C;
    *(const void**)p = (const char*)vt + 84;
    p -= 0x38;
    *(const void**)p = vt;
    func_004B9AA0(p);
}
