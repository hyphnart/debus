#pragma once
#include "DisassemblyEngine.h"
#include "CrossReferenceEngine.h"
#include <QVector>
#include <QString>

// Heuristic regions in a *single linear disassembly window*, not verified functions.
struct FunctionRegion {
    quint64 entry=0;
    quint64 lastAddress=0;
    int instructionCount=0;
    int directCallers=0;
    bool entryInWindow=false;
    bool terminatesWithReturn=false;
};
struct FunctionCallEdge {
    quint64 callerRegion=0;
    quint64 instructionAddress=0;
    quint64 target=0;
    bool targetInWindow=false;
};
struct FunctionAnalysisReport {
    QVector<FunctionRegion> regions;
    QVector<FunctionCallEdge> calls;
    QString warning;
};
class FunctionAnalysisEngine {
public:
    static FunctionAnalysisReport analyze(const DisassemblyReport &disassembly);
};
