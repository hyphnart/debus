#pragma once
#include <QString>
#include <QVector>
struct Instruction { quint64 address=0; QString bytes,mnemonic,operands; };
struct DisassemblyReport { QString error; QVector<Instruction> instructions; quint64 startAddress=0; bool available=false; };
class DisassemblyEngine {
public:
    // Raw file-offset disassembly, not automatic code discovery.
    static DisassemblyReport decode(const QString &path,quint64 offset,quint64 virtualAddress,
                                    bool x64,int maxInstructions=300);
};
