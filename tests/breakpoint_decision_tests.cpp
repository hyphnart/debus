#include "BreakpointDecision.h"
#include <cassert>
int main(){
    DebugStopRecord sample{};sample.accumulator=0x5;
    TraceStopCondition cond{};cond.field=TraceStopCondition::Field::Rax;cond.equals=0x5;
    auto matched=evaluateBreakpoint(cond,sample,1234,1234,true);
    assert(matched.threadMatched && matched.conditionMatched && matched.shouldPause);
    auto wrongThreadSafe=evaluateBreakpoint(cond,sample,1234,4321,false);
    assert(!wrongThreadSafe.threadMatched && wrongThreadSafe.conditionMatched);
    assert(wrongThreadSafe.shouldPause && !wrongThreadSafe.shouldAutoContinue);
    auto wrongThreadSkip=evaluateBreakpoint(cond,sample,1234,4321,true);
    assert(!wrongThreadSkip.shouldPause && wrongThreadSkip.shouldAutoContinue);
    sample.accumulator=2;
    auto wrongValueSafe=evaluateBreakpoint(cond,sample,1234,1234,false);
    assert(wrongValueSafe.shouldPause && !wrongValueSafe.conditionMatched);
    auto wrongValueSkip=evaluateBreakpoint(cond,sample,1234,1234,true);
    assert(!wrongValueSkip.shouldPause);
    TraceStopCondition noCondition{};
    auto threadOnly=evaluateBreakpoint(noCondition,sample,1234,1234,true);
    assert(threadOnly.shouldPause && threadOnly.conditionMatched);
    auto threadOnlyWrong=evaluateBreakpoint(noCondition,sample,1234,4321,true);
    assert(!threadOnlyWrong.shouldPause);
    BreakpointStatistics stats;
    stats.record(matched);
    stats.record(wrongThreadSafe);
    stats.record(wrongThreadSkip,true);
    stats.record(wrongValueSafe);
    stats.record(wrongValueSkip,true);
    assert(stats.hits==5);
    assert(stats.threadMatches==3);
    assert(stats.conditionMatches==1);
    assert(stats.effectiveMatches==1);
    assert(stats.automaticContinues==2);
    return 0;
}
