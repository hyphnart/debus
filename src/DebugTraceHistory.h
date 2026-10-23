#pragma once
#include <cstdint>
#include <deque>
#include <string>
#include <vector>
#include <utility>
// Snapshots are recorded only at *debugger stops*, not at every instruction.
// Separate from Qt/Win32 so state bookkeeping can be tested on Linux and Windows.
struct DebugStopRecord {
    std::uint64_t sequence=0;
    std::uint32_t thread=0;
    std::uint64_t instructionPointer=0;
    std::uint64_t accumulator=0;
    std::uint64_t stackPointer=0;
    std::uint64_t flags=0;
    std::string cause;
};
class DebugTraceHistory {
public:
    explicit DebugTraceHistory(std::size_t capacity=512):capacity_(capacity ? capacity : 1) {}
    const DebugStopRecord &append(DebugStopRecord record) {
        record.sequence=++sequence_;
        if(items_.size()==capacity_)items_.pop_front();
        items_.push_back(std::move(record));
        return items_.back();
    }
    const std::deque<DebugStopRecord> &items() const {return items_;}
    std::uint64_t total() const {return sequence_;}
    void reset(){items_.clear();sequence_=0;}
private:
    std::size_t capacity_;
    std::uint64_t sequence_=0;
    std::deque<DebugStopRecord> items_;
};
