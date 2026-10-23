#include "DiffEngine.h"
#include <QFile>
#include <algorithm>
DiffReport DiffEngine::compare(const QString &left,const QString &right,Progress progress) {
    DiffReport r;
    QFile a(left),b(right);
    if(!a.open(QIODevice::ReadOnly) || !b.open(QIODevice::ReadOnly)) {
        r.error="Cannot open one or both files.";return r;
    }
    r.leftSize=a.size();r.rightSize=b.size();
    const qint64 total=std::max(r.leftSize,r.rightSize);
    constexpr qint64 chunk=1024*1024;
    constexpr int maxRanges=100000;
    qint64 pos=0;
    bool active=false;
    DiffRange current;
    auto finish=[&](){
        if(!active)return;
        if(r.ranges.size()<maxRanges) r.ranges.append(current);
        else r.truncated=true;
        active=false;
    };
    while(pos<total) {
        if(progress && !progress(pos,total)) {r.cancelled=true;r.error="Cancelled.";return r;}
        qint64 take=std::min(chunk,total-pos);
        QByteArray x=a.read(take),y=b.read(take);
        if(x.size()!=std::min(take,std::max<qint64>(0,r.leftSize-pos)) ||
           y.size()!=std::min(take,std::max<qint64>(0,r.rightSize-pos))) {
            r.error="File read failed or file size changed.";return r;
        }
        for(qint64 i=0;i<take;++i) {
            bool different=(i>=x.size() || i>=y.size() || x.at(i)!=y.at(i));
            if(different) {
                ++r.changedBytes;
                if(!active) {active=true;current={pos+i,0};}
                ++current.length;
            } else finish();
        }
        pos+=take;
    }
    finish();
    if(progress) progress(total,total);
    return r;
}
