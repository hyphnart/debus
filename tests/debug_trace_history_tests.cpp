#include "DebugTraceHistory.h"
#include <cassert>
#include <iostream>
int main(){
    DebugTraceHistory h(3);
    for(unsigned i=0;i<5;++i){
        DebugStopRecord r;
        r.thread=(i%2)+1;r.instructionPointer=0x401000+i;
        r.accumulator=i;r.cause="single-step";
        assert(h.append(r).sequence==i+1);
    }
    assert(h.total()==5 && h.items().size()==3);
    assert(h.items().front().sequence==3);
    assert(h.items().back().instructionPointer==0x401004);
    assert(h.items().back().thread==1);
    h.reset();assert(h.items().empty() && h.total()==0);
    std::cout<<"PASS: bounded debugger stop history\n";
}
