// 0x503368: D1 destructor of an object at vtable 006EE3BC: writes the vtable,
// runs the child member dtor (0030E0F0), then tail-calls the base dtor
// (002312F4) with this adjusted back by -0x184. Twin of func_00152CB4.cpp.
struct ChildD {
    ~ChildD();          // D1 = 0030E0F0
    char pad[0x15c];
};

struct BaseD {
    virtual ~BaseD();   // D1 = 002312F4
    char pad[0x180];
};

struct ObjD : BaseD {
    ChildD child;
    virtual ~ObjD();    // vt 006EE3BC
};

ObjD::~ObjD() {}
