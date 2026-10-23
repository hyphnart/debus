#pragma once
#include "DisassemblyEngine.h"
#include <QVector>
#include <QString>
struct DirectReference { quint64 from=0,to=0; QString mnemonic; bool targetInWindow=false; };
struct FunctionCandidate { quint64 entry=0; int callCount=0; bool inWindow=false; };
struct CrossReferenceReport { QVector<DirectReference> references; QVector<FunctionCandidate> functions; QString note; };
class CrossReferenceEngine {
public:
    static CrossReferenceReport analyze(const DisassemblyReport &report);
};
