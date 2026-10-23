#include "ConditionalBreakpointPolicy.h"
#include <cassert>
int main() {
    ConditionalBreakpointPolicy p;
    DebugStopRecord r{};r.accumulator=2;
    assert(p.shouldStop(r));assert(p.hits==1);
    p.condition.field=TraceStopCondition::Field::Rax;p.condition.equals=5;
    p.skipUnmatched=true;
    assert(!p.shouldStop(r));assert(p.hits==2 && p.matches==0);
    r.accumulator=5;
    assert(p.shouldStop(r));assert(p.hits==3 && p.matches==1);
    p.skipUnmatched=false;r.accumulator=6;
    assert(p.shouldStop(r));assert(p.hits==4 && p.matches==1);
    return 0;
}
