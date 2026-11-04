// 0x687EA0: twin of 00687DB0/00687E28 (guarded RTTI dynamic-cast-style check).
#include "../../work7/gpt22/range.h"
#include "sead_rtti.h"
struct RttiSourceA0{virtual bool checkDerivedRuntimeTypeInfo(const sead::RuntimeTypeInfo::Interface*)const;};
struct RttiTargetA0:RttiSourceA0{SEAD_RTTI_BASE(RttiTargetA0)};
extern RttiTargetA0* target(RttiSourceA0*p){const sead::RuntimeTypeInfo::Interface*info=RttiTargetA0::getRuntimeTypeInfoStatic();if(p&&p->checkDerivedRuntimeTypeInfo(info))return static_cast<RttiTargetA0*>(p);return 0;}
