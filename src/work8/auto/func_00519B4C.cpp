// func_00519B4C — guard + step + tail-call update on a sub-object (64B).
//
// Target shape (differs from siblings 0043DD2C / 00519544): the guard
// materializes a boolean (movne r1,#0; moveq r1,#1; teq r1,#1; beq) rather
// than branching off cmpeq directly. That suggests the source returns a
// bool computed from the two state bytes, then tests it.
//
//   r0 = this->sub ([this, #0xf4])
//   r1 = (sub->d != 0 || sub->e != 0) ? 0 : 1   as: cmp d; ldrbeq e; cmpeq; movne 0; moveq 1
//   teq r1,#1; beq end                          -> if (idle) return;
//   bl func_0012C790(sub)
//   r0 = this->sub reloaded
//   pop {r4,lr}; b func_001B6B38                (tail call)

typedef unsigned char u8;

struct Sub {
    u8 _00[0xd];
    u8 d;
    u8 e;
};

struct Owner {
    u8 _00[0xf4];
    Sub* sub;
};

extern void func_0012C790(void* arg);
extern void func_001B6B38(void* arg);

void func_00519B4C(Owner* this_) {
    int idle;
    if (this_->sub->d != 0)
        idle = 0;
    else
        idle = (this_->sub->e == 0);
    if (idle == 1) {
        return;
    }
    func_0012C790(this_->sub);
    func_001B6B38(this_->sub);
}
