#pragma once
#include <QString>
#include <QVector>
#include <QByteArray>
#include <QtGlobal>
struct BreakpointPreset {
    quint64 address=0;
    QString field;
    quint64 value=0;
    quint32 threadId=0; // 0 = any thread
    bool skipUnmatched=false;
};
class BreakpointPresetCodec {
public:
    static QByteArray encode(const QVector<BreakpointPreset> &items);
    static bool decode(const QByteArray &json,QVector<BreakpointPreset> &items,QString &error);
};
