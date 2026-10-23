#include "BreakpointState.h"
#include <cassert>
#include <iostream>
int main(){
    BreakpointState state;
    assert(!state.install(0x1000,0x90,false,false));
    assert(state.install(0x1000,0x90,false,true));
    assert(!state.install(0x1000,0x90,false,true));
    assert(!state.hit(0x1000,false,true));
    assert(state.find(0x1000)->armed);
    assert(!state.hit(0x1000,true,false));
    assert(state.hit(0x1000,true,true));
    assert(!state.find(0x1000)->armed);
    assert(!state.rearm(0x1000,false));
    assert(state.rearm(0x1000,true));
    assert(!state.remove(0x1000,false));
    assert(state.remove(0x1000,true));
    assert(!state.find(0x1000));
    assert(state.install(0x2000,0xC3,true,true));
    assert(state.hit(0x2000,true,true));
    assert(state.count()==0);
    std::cout << "PASS: breakpoint transition invariants" << std::endl;
}
