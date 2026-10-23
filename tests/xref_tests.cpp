#include "CrossReferenceEngine.h"
#include <QCoreApplication>
#include <QDebug>
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    DisassemblyReport decoded;
    decoded.instructions.append({0x1000,"E8 FB 00 00 00","call","0x1100"});
    decoded.instructions.append({0x1005,"74 05","je","0x100c"});
    decoded.instructions.append({0x1007,"FF D0","call","rax"});
    decoded.instructions.append({0x1009,"C3","ret",""});
    decoded.instructions.append({0x100c,"C3","ret",""});
    const auto report=CrossReferenceEngine::analyze(decoded);
    if(report.references.size()!=2 || report.functions.size()!=1 ||
       report.functions[0].entry!=0x1100 || report.functions[0].callCount!=1 ||
       report.functions[0].inWindow || !report.references[1].targetInWindow) {
        qCritical()<<"FAIL: direct references and function candidates";
        return 1;
    }
    qInfo()<<"PASS: direct references and function candidates";
    return 0;
}
