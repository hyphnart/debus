#include "FunctionAnalysisEngine.h"
#include <QMap>
#include <QSet>
#include <algorithm>
namespace {
bool isReturn(const QString &op) {
    return op.startsWith("ret") || op=="iret" || op=="iretq";
}
}
FunctionAnalysisReport FunctionAnalysisEngine::analyze(const DisassemblyReport &disassembly) {
    FunctionAnalysisReport result;
    const auto &instructions=disassembly.instructions;
    if(instructions.isEmpty()) {
        result.warning="No decoded instructions.";
        return result;
    }
    const auto xrefs=CrossReferenceEngine::analyze(disassembly);
    QMap<quint64,int> index;
    for(int i=0;i<instructions.size();++i) index.insert(instructions[i].address,i);
    QMap<quint64,int> directCallers;
    QSet<int> leaders;
    leaders.insert(0);
    for(const auto &f:xrefs.functions) {
        directCallers[f.entry]=f.callCount;
        if(index.contains(f.entry))leaders.insert(index.value(f.entry));
    }
    // A RET boundary is only a possible function boundary; linear data may follow.
    for(int i=0;i+1<instructions.size();++i) {
        if(isReturn(instructions[i].mnemonic.toLower()))leaders.insert(i+1);
    }
    QList<int> sorted=leaders.values();
    std::sort(sorted.begin(),sorted.end());
    QMap<quint64,quint64> owner;
    for(int k=0;k<sorted.size();++k) {
        const int begin=sorted[k];
        const int end=(k+1<sorted.size()?sorted[k+1]:instructions.size())-1;
        FunctionRegion region;
        region.entry=instructions[begin].address;
        region.lastAddress=instructions[end].address;
        region.instructionCount=end-begin+1;
        region.entryInWindow=true;
        region.directCallers=directCallers.value(region.entry,0);
        region.terminatesWithReturn=isReturn(instructions[end].mnemonic.toLower());
        for(int i=begin;i<=end;++i)owner.insert(instructions[i].address,region.entry);
        result.regions.append(region);
    }
    for(const auto &ref:xrefs.references) {
        if(ref.mnemonic!="call" && ref.mnemonic!="lcall")continue;
        result.calls.append({owner.value(ref.from,0),ref.from,ref.to,ref.targetInWindow});
    }
    for(const auto &f:xrefs.functions) {
        if(f.inWindow)continue;
        FunctionRegion external;
        external.entry=f.entry;
        external.directCallers=f.callCount;
        external.entryInWindow=false;
        result.regions.append(external);
    }
    result.warning="Function regions are heuristic: direct CALL targets, decoded-window start and post-RET boundaries. "
        "No recursive descent, tail-call recovery, exception-edge analysis, or indirect call resolution.";
    return result;
}
