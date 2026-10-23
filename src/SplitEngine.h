#pragma once
#include <QString>
#include <functional>
class SplitEngine {
public:
    using Progress = std::function<bool(qint64 done,qint64 total)>;
    static bool split(const QString &source,const QString &destination,
                      qint64 partSize,const Progress &progress,QString &error,
                      int compressionLevel=0);
    static bool join(const QString &manifest,const QString &destination,
                     const Progress &progress,QString &error);
};
