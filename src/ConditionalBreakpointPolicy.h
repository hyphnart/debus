#pragma once
#include "TraceStopCondition.h"
#include <cstdint>
struct ConditionalBreakpointPolicy {
    TraceStopCondition condition{};
    std::uint64_t hits=0;
    std::uint64_t matches=0;
    bool skipUnmatched=false;
    // An unspecified rule always stops. Explicit condition optionally skips mismatches.
    bool shouldStop(const DebugStopRecord &sample) noexcept {
        ++hits;
        if(condition.field==TraceStopCondition::Field::None)return true;
        const bool matched=condition.matches(sample);
        if(matched)++matches;
        return matched || !skipUnmatched;
    }
};
