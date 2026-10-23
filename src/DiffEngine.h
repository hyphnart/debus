#pragma once
#include <QString>
#include <QVector>
#include <functional>
struct DiffRange { qint64 offset=0,length=0; };
struct DiffReport {
    qint64 leftSize=0,rightSize=0,changedBytes=0;
    QVector<DiffRange> ranges;
    bool truncated=false,cancelled=false;
    QString error;
};
class DiffEngine {
public:
    using Progress=std::function<bool(qint64,qint64)>;
    static DiffReport compare(const QString &left,const QString &right,Progress progress={});
};
