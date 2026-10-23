#include "ControlFlowEngine.h"
#include <QMap>
#include <QSet>
#include <algorithm>
#include <limits>
namespace {
bool parseImmediate(QString operand,quint64 &target) {
    operand=operand.trimmed();
    if(operand.startsWith("0x",Qt::CaseInsensitive)) operand=operand.mid(2);
    bool ok=false;
    target=operand.toULongLong(&ok,16);
    return ok;
}
bool isCall(const QString &op) {return op=="call" || op=="lcall";}
bool isJump(const QString &op) {return op=="jmp" || op=="ljmp";}
bool isConditional(const QString &op) {
    return (op.startsWith('j') && !isJump(op)) ||
        op=="loop" || op=="loope" || op=="loopne" || op=="jcxz" || op=="jecxz" || op=="jrcxz";
}
bool isReturn(const QString &op) {return op.startsWith("ret") || op=="iret" || op=="iretq";}
}
FlowReport ControlFlowEngine::build(const DisassemblyReport &input) {
    FlowReport out;
    const auto &ins=input.instructions;
    if(ins.isEmpty()) {out.warning="No decoded instructions.";return out;}
    QMap<quint64,int> index;
    for(int i=0;i<ins.size();++i) index.insert(ins[i].address,i);
    QSet<quint64> starts;
    starts.insert(ins.first().address);
    for(int i=0;i<ins.size();++i) {
        const auto &v=ins[i];
        QString op=v.mnemonic.toLower();
        const bool branch=isCall(op)||isJump(op)||isConditional(op);
        if(branch) {
            quint64 target=0;
            if(parseImmediate(v.operands,target) && index.contains(target))
                starts.insert(target);
        }
        if((branch||isReturn(op)) && i+1<ins.size()) starts.insert(ins[i+1].address);
    }
    int first=0;
    for(int i=1;i<=ins.size();++i) {
        if(i==ins.size() || starts.contains(ins[i].address)) {
            FlowBlock block;
            block.firstInstruction=first;
            block.lastInstruction=i-1;
            block.start=ins[first].address;
            block.endExclusive=ins[i-1].address+static_cast<quint64>(ins[i-1].bytes.split(' ',Qt::SkipEmptyParts).size());
            out.blocks.append(block);
            first=i;
        }
    }
    for(const auto &block:out.blocks) {
        const int last=block.lastInstruction;
        const auto &v=ins[last];
        const QString op=v.mnemonic.toLower();
        const bool call=isCall(op),jump=isJump(op),conditional=isConditional(op),ret=isReturn(op);
        auto edge=[&](quint64 target,const QString &kind){
            out.edges.append({block.start,target,kind,index.contains(target)});
        };
        if(call||jump||conditional) {
            quint64 target=0;
            if(parseImmediate(v.operands,target)) edge(target,call?"call":jump?"jump":"conditional");
            else edge(0,call?"indirect call":jump?"indirect jump":"indirect branch");
        }
        if(last+1<ins.size() && !ret && !jump)
            edge(ins[last+1].address,call?"return-site":conditional?"false branch":"fallthrough");
    }
    out.warning="Graph covers only the decoded linear instruction window; unreachable bytes and indirect targets are not resolved.";
    return out;
}
