#include "CrossReferenceEngine.h"
#include <QMap>
#include <QSet>
#include <algorithm>
namespace {
bool directTarget(QString value,quint64 &out) {
    value=value.trimmed();
    if(value.startsWith("0x",Qt::CaseInsensitive)) value=value.mid(2);
    if(value.isEmpty())return false;
    for(const QChar ch:value) if(!ch.isDigit() && !(ch.toLower()>='a' && ch.toLower()<='f'))return false;
    bool ok=false;
    out=value.toULongLong(&ok,16);
    return ok;
}
bool branch(const QString &op) {
    return op=="call" || op=="lcall" || op=="jmp" || op=="ljmp" ||
           (op.startsWith('j') && op!="jmp") || op.startsWith("loop");
}
}
CrossReferenceReport CrossReferenceEngine::analyze(const DisassemblyReport &report) {
    CrossReferenceReport result;
    QSet<quint64> decoded;
    for(const auto &ins:report.instructions)decoded.insert(ins.address);
    QMap<quint64,int> calls;
    for(const auto &ins:report.instructions) {
        const QString op=ins.mnemonic.toLower();
        if(!branch(op))continue;
        quint64 target=0;
        if(!directTarget(ins.operands,target))continue;
        result.references.append({ins.address,target,op,decoded.contains(target)});
        if(op=="call" || op=="lcall")++calls[target];
    }
    for(auto it=calls.cbegin();it!=calls.cend();++it)
        result.functions.append({it.key(),it.value(),decoded.contains(it.key())});
    result.note="Function candidates are direct CALL targets only. No function boundary recovery or indirect call resolution.";
    return result;
}
