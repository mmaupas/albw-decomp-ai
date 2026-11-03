// 0x655BF0: twin of 00654C3C (kind!=5 guard + timer + selected clear).
#include "../../work7/gpt30/range.h"
extern "C" void func_004FC570(ActorFocus30*);
extern "C" void target(ActorFocus30* p, s32 kind) {
    if (kind == 5) return;
    func_004FC570(p);
    p->timer = 150;
    u32* selected = &data_00706E20->focus->selected;
    if (*selected && *selected == p->id) *selected = 0;
}
