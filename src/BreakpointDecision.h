#pragma once
#include "TraceStopCondition.h"
#include <cstdint>

// Pure decision logic. Never mutates user policies or counters.
struct BreakpointDecision {
    bool threadMatched=false;
    bool conditionMatched=false;
    bool shouldPause=true;
    bool shouldAutoContinue=false;
};
struct BreakpointStatistics {
    std::uint64_t hits=0;
    std::uint64_t threadMatches=0;
    std::uint64_t conditionMatches=0;
    std::uint64_t effectiveMatches=0;
    std::uint64_t automaticContinues=0;
    void record(const BreakpointDecision &d,bool actuallyContinued=false) noexcept {
        ++hits;
        if(d.threadMatched)++threadMatches;
        if(d.threadMatched && d.conditionMatched)++conditionMatches;
        if(d.threadMatched && d.conditionMatched)++effectiveMatches;
        if(actuallyContinued)++automaticContinues;
    }
};
inline BreakpointDecision evaluateBreakpoint(
    const TraceStopCondition &condition,
    const DebugStopRecord &record,
    std::uint32_t permittedThread,
    std::uint32_t eventThread,
    bool skipUnmatched) noexcept {
    BreakpointDecision d;
    d.threadMatched=(permittedThread==0 || permittedThread==eventThread);
    d.conditionMatched=(condition.field==TraceStopCondition::Field::None || condition.matches(record));
    const bool effective=d.threadMatched && d.conditionMatched;
    // Safe default: Always Pause does not silently auto-continue a filtered thread.
    d.shouldPause=!skipUnmatched || effective;
    d.shouldAutoContinue=!d.shouldPause;
    return d;
}
