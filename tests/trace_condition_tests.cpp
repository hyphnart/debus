#include "TraceStopCondition.h"
#include <cassert>
#include <iostream>
int main(){
 DebugStopRecord record{}; record.instructionPointer=0x401000; record.accumulator=7;record.stackPointer=0x2000;record.flags=0x40;
 TraceStopCondition c{};assert(!c.matches(record));
 c.field=TraceStopCondition::Field::Rip;c.equals=0x401000;assert(c.matches(record));
 c.equals=0x401001;assert(!c.matches(record));
 c.field=TraceStopCondition::Field::Rax;c.equals=7;assert(c.matches(record));
 c.field=TraceStopCondition::Field::Rsp;c.equals=0x2000;assert(c.matches(record));
 c.field=TraceStopCondition::Field::Zf;c.equals=1;assert(c.matches(record));
 c.equals=0;assert(!c.matches(record));
 std::cout << "PASS: trace stop predicates\n";
}
