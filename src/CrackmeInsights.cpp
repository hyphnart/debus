#include "CrackmeInsights.h"
#include <QSet>
#include <algorithm>
namespace {
bool isCompare(const QString &s) {
    return s=="cmp" || s=="test" || s=="comiss" || s=="ucomiss" || s=="comisd" || s=="ucomisd";
}
bool isConditionalBranch(const QString &s) {
    return (s.startsWith('j') && s!="jmp" && s!="ljmp") ||
           s=="loop" || s=="loope" || s=="loopne";
}
bool isDirectHex(QString text) {
    text=text.trimmed();
    if(!text.startsWith("0x",Qt::CaseInsensitive)) return false;
    bool ok=false;
    text.mid(2).toULongLong(&ok,16);
    return ok;
}
}
QVector<CrackmeInsight> CrackmeInsights::scan(const DisassemblyReport &report) {
    QVector<CrackmeInsight> out;
    const auto &ins=report.instructions;
    // Only local instruction patterns; no claims about licensing, secrets or a 'correct' path.
    constexpr int maxResults=300;
    for(int i=0;i<ins.size() && out.size()<maxResults;++i) {
        const QString op=ins[i].mnemonic.trimmed().toLower();
        const QString operands=ins[i].operands.trimmed();
        if(isCompare(op)) {
            // Only pair with the immediately following instruction to avoid false dataflow claims.
            if(i+1<ins.size() && isConditionalBranch(ins[i+1].mnemonic.trimmed().toLower())) {
                const auto &next=ins[i+1];
                out.append({ins[i].address,"Compare + branch",
                    QString("%1 %2  →  %3 %4")
                        .arg(op,operands,next.mnemonic,next.operands),
                    "Branch direction depends on runtime flags; no result is inferred."});
            }
        }
        if(op=="call" && isDirectHex(operands)) {
            out.append({ins[i].address,"Direct call",QString("Call target: %1").arg(operands),
                "Direct calls can be inspected via Function/XREF views."});
        }
        if(op=="int" && (operands=="3" || operands=="0x3")) {
            out.append({ins[i].address,"Breakpoint instruction","INT 3 in decoded bytes",
                "Could be intentional or a compiler/debug artifact."});
        }
    }
    return out;
}
