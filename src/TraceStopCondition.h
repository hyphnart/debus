#pragma once
#include <cstdint>
#include "DebugTraceHistory.h"
// Deliberately narrow, deterministic predicate grammar; no evaluation of untrusted expressions.
struct TraceStopCondition {
    enum class Field { None, Rip, Rax, Rsp, Zf };
    Field field=Field::None;
    std::uint64_t equals=0;
    bool matches(const DebugStopRecord &record) const noexcept {
        switch(field) {
            case Field::Rip:return record.instructionPointer==equals;
            case Field::Rax:return record.accumulator==equals;
            case Field::Rsp:return record.stackPointer==equals;
            case Field::Zf:return ((record.flags>>6)&1U)==equals;
            case Field::None:return false;
        }
        return false;
    }
};
