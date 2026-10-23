#pragma once
#include <cstdint>
#include <map>

// Unit-testable breakpoint bookkeeping. This model does not itself patch memory.
// A transition is committed only if the OS operation actually succeeded.
class BreakpointState {
public:
    struct Entry {unsigned char original=0; bool armed=false; bool temporary=false;};
    bool install(std::uint64_t address,unsigned char original,bool temporary,bool patchSucceeded) {
        if(!patchSucceeded || entries_.count(address))return false;
        entries_.emplace(address,Entry{original,true,temporary});return true;
    }
    bool hit(std::uint64_t address,bool restoreSucceeded,bool rewindSucceeded) {
        auto it=entries_.find(address);
        if(it==entries_.end()||!it->second.armed||!restoreSucceeded||!rewindSucceeded)return false;
        if(it->second.temporary)entries_.erase(it);
        else it->second.armed=false;
        return true;
    }
    bool rearm(std::uint64_t address,bool patchSucceeded) {
        auto it=entries_.find(address);
        if(it==entries_.end()||it->second.armed||!patchSucceeded)return false;
        it->second.armed=true;return true;
    }
    bool remove(std::uint64_t address,bool restoreSucceeded) {
        auto it=entries_.find(address);
        if(it==entries_.end()||(it->second.armed&&!restoreSucceeded))return false;
        entries_.erase(it);return true;
    }
    const Entry *find(std::uint64_t address) const {
        auto it=entries_.find(address);
        return it==entries_.end()?nullptr:&it->second;
    }
    std::size_t count()const{return entries_.size();}
private:
    std::map<std::uint64_t,Entry> entries_;
};
