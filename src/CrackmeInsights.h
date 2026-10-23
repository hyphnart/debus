#pragma once
#include "DisassemblyEngine.h"
#include <QString>
#include <QVector>
struct CrackmeInsight {
    quint64 address=0;
    QString category;
    QString detail;
    QString caution;
};
class CrackmeInsights {
public:
    // Read-only heuristics for learning/CTF crackme analysis; not an execution debugger.
    static QVector<CrackmeInsight> scan(const DisassemblyReport &report);
};
