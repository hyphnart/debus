#pragma once
#include <QString>
#include <QVector>
#include <QByteArray>
#include <functional>
struct EntropyBlock { qint64 offset=0; qint64 size=0; double bitsPerByte=0; };
struct ExtractedString { qint64 offset=0; QString encoding; QString value; };
struct AnalysisReport {
    QString fileType;
    QString signature;
    qint64 fileSize=0;
    QVector<EntropyBlock> entropy;
    QVector<ExtractedString> strings;
    QString error;
    bool cancelled=false;
};
class AnalysisEngine {
public:
    using Progress=std::function<bool(qint64,qint64)>;
    static AnalysisReport analyze(const QString &path,Progress progress={});
};
