// 0x4D9D28: D1 destructor of an object at vtable 006C8FC8. Writes the vtable,
// re-points an embedded sub-object vtable at vt+0x54 (offset 0x320), runs the
// member dtor (004EE540), then tail-calls the base dtor (001510A4) with this
// adjusted back by -0x440. Twin of src/work7/gpt15/variants/00149B40/v0.cpp.
typedef unsigned int u32;
typedef unsigned char u8;
struct Primary {
    u8 pad[0x31c];
    virtual ~Primary();
    virtual void v0();  virtual void v1();  virtual void v2();  virtual void v3();
    virtual void v4();  virtual void v5();  virtual void v6();  virtual void v7();
    virtual void v8();  virtual void v9();  virtual void v10(); virtual void v11();
    virtual void v12(); virtual void v13(); virtual void v14(); virtual void v15();
    virtual void v16();
};
struct Secondary {
    u8 pad[0x11c];
    virtual ~Secondary();
};
struct Base_001510A4 : Primary, Secondary {
    virtual ~Base_001510A4();       // D1 = 001510A4
};
struct Member_004EE540 {
    u32 data;
    ~Member_004EE540();             // D1 = 004EE540
};
struct S : Base_001510A4 {
    Member_004EE540 m;              // sub-object vt at +0x320, patched to vt+0x54
    virtual ~S();                   // vt 006C8FC8
};
S::~S() {}
