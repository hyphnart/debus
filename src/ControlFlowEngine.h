#pragma once
#include "DisassemblyEngine.h"
#include <QVector>
#include <QString>
struct FlowBlock {
    quint64 start=0,endExclusive=0;
    int firstInstruction=0,lastInstruction=0;
};
struct FlowEdge {
    quint64 from=0,to=0;
    QString kind;
    bool targetDecoded=false;
};
struct FlowReport {
    QVector<FlowBlock> blocks;
    QVector<FlowEdge> edges;
    QString warning;
};
class ControlFlowEngine {
public:
    // Conservative basic-block graph from a *linear decoded window*.
    // Indirect branch targets are not guessed; external targets are labeled.
    static FlowReport build(const DisassemblyReport &input);
};
