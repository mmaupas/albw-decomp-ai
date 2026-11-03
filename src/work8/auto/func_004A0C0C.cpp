// 0x4A0C0C: D1 destructor, twin of func_0048E8AC (1.00 DNA match).
// vtable store at [r0] with writeback #0x30 (member offset 0x30),
// member dtor call (00498290), return adjusted this (sub r0,#0x30).
// Member size 0x30.
struct MemA0C { char pad[0x30]; ~MemA0C(); };
struct OA0C { virtual ~OA0C(); char pre[0x2c]; MemA0C member; };
OA0C::~OA0C() {}
