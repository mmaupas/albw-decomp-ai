#include "../game/gpt30/npc_exec136.h"
extern "C" void func_00352210(void*, bool, float);
extern "C" void func_004BCAA8(NpcExec30*);
extern "C" void func_004BC8D8(NpcExec30*);
struct NpcExecState30X {
    u32 frame;s8 current,previous;u8 pad6[2];u32 count;void* names;
    void* timeline;ExecOwner30* owner;ExecMethod30* enter;ExecMethod30* exec;ExecMethod30* exit;
    void execute(){
        (owner->*exec[current])();
        ++frame;
        if(timeline)func_00352210(timeline,true,static_cast<f32>(frame));
    }
};
struct NpcExec30X {u8 pad0[0x960];NpcExecState30X state;};
void target(NpcExec30X* p) {
    p->state.execute();
    func_004BCAA8((NpcExec30*)p);
    func_004BC8D8((NpcExec30*)p);
}
