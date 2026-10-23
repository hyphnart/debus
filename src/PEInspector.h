#pragma once
#include <QString>
#include <QVector>
struct PESection {
    QString name;
    quint32 virtualAddress=0, virtualSize=0, rawOffset=0, rawSize=0;
};
struct PEImport { QString dll; QVector<QString> functions; };
struct PEReport {
    bool valid=false;
    QString error;
    QString architecture;
    quint16 machine=0;
    quint16 sectionCount=0;
    quint64 imageBase=0;
    quint32 entryPointRva=0;
    QVector<PESection> sections;
    QVector<PEImport> imports;
    QString importWarning;
};
class PEInspector {
public:
    static PEReport inspect(const QString &path);
    // Maps a PE RVA to an on-disk byte offset, validating the mapped extent.
    static bool rvaToFileOffset(const PEReport &report,quint32 rva,quint64 fileSize,quint64 &offset);
};
