#include "BreakpointPreset.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QSet>
#include <limits>
#include <utility>
namespace {
bool validField(const QString &value){
    return value.isEmpty() || value=="RIP" || value=="RAX" || value=="RSP" || value=="ZF";
}
bool parseHex(const QJsonValue &v,quint64 &out) {
    if(!v.isString())return false;
    QString str=v.toString();
    if(str.startsWith("0x",Qt::CaseInsensitive))str=str.mid(2);
    if(str.isEmpty() || str.size()>16)return false;
    for(const QChar ch:str){
        const ushort c=ch.unicode();
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')))return false;
    }
    bool ok=false;
    out=str.toULongLong(&ok,16);
    return ok;
}
}
QByteArray BreakpointPresetCodec::encode(const QVector<BreakpointPreset> &items) {
    QJsonArray entries;
    for(const auto &b:items) {
        QJsonObject obj;
        obj["address"]=QString::number(b.address,16);
        obj["field"]=b.field.toUpper();
        obj["value"]=QString::number(b.value,16);
        obj["threadId"]=static_cast<qint64>(b.threadId);
        obj["skipUnmatched"]=b.skipUnmatched;
        entries.append(obj);
    }
    QJsonObject root;
    root["format"]="YAS-BREAKPOINT-PRESETS-1";
    root["breakpoints"]=entries;
    return QJsonDocument(root).toJson(QJsonDocument::Indented);
}
bool BreakpointPresetCodec::decode(const QByteArray &json,QVector<BreakpointPreset> &items,QString &error) {
    QJsonParseError parseError;
    const auto document=QJsonDocument::fromJson(json,&parseError);
    if(parseError.error!=QJsonParseError::NoError || !document.isObject()) {
        error="Invalid JSON: "+parseError.errorString();return false;
    }
    const auto root=document.object();
    if(root.value("format")!="YAS-BREAKPOINT-PRESETS-1" || !root.value("breakpoints").isArray()){
        error="Unsupported breakpoint preset format.";return false;
    }
    const auto list=root.value("breakpoints").toArray();
    if(list.size()>4096){error="Maximum 4096 breakpoints allowed.";return false;}
    QVector<BreakpointPreset> parsed;
    QSet<quint64> addresses;
    for(const auto &entry:list){
        if(!entry.isObject()){error="Breakpoint entry must be an object.";return false;}
        const auto obj=entry.toObject();
        BreakpointPreset b;
        if(!parseHex(obj.value("address"),b.address) || !b.address || addresses.contains(b.address) ||
           !parseHex(obj.value("value"),b.value)){
            error="Invalid, empty or duplicate breakpoint address/value.";return false;
        }
        b.field=obj.value("field").toString().toUpper();
        if(!validField(b.field) || (b.field=="ZF" && b.value>1)){
            error="Unsupported condition field/value.";return false;
        }
        const auto thread=obj.value("threadId");
        if(!thread.isDouble() || thread.toDouble()<0 || thread.toDouble()>4294967295.0 ||
           static_cast<double>(static_cast<quint32>(thread.toDouble()))!=thread.toDouble()){
            error="Invalid thread id.";return false;
        }
        b.threadId=static_cast<quint32>(thread.toDouble());
        if(!obj.value("skipUnmatched").isBool()){
            error="Invalid skipUnmatched value.";return false;
        }
        b.skipUnmatched=obj.value("skipUnmatched").toBool();
        addresses.insert(b.address);
        parsed.append(b);
    }
    items=std::move(parsed);
    error.clear();
    return true;
}
