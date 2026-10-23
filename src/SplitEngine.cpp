#include "SplitEngine.h"
#include <QFile>
#include <QSaveFile>
#include <QDir>
#include <QFileInfo>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <algorithm>
#include <limits>
#include <QtEndian>
#include <QSet>

namespace {
constexpr qint64 bufferSize=1024*1024;
QString digest(const QByteArray &data) {
    return QString::fromLatin1(QCryptographicHash::hash(data,QCryptographicHash::Sha256).toHex());
}
bool writeAll(QIODevice &out,const QByteArray &data) {
    qint64 offset=0;
    while(offset<data.size()) {
        qint64 written=out.write(data.constData()+offset,data.size()-offset);
        if(written<=0) return false;
        offset+=written;
    }
    return true;
}
QString hashResult(QCryptographicHash &h) {
    return QString::fromLatin1(h.result().toHex());
}
bool safeName(const QString &name) {
    return !name.isEmpty() && name!="." && name!=".." &&
        !name.contains('/') && !name.contains('\\') && !name.contains(':');
}
}
bool SplitEngine::split(const QString &source,const QString &destination,
                        qint64 partSize,const Progress &progress,QString &error,int compressionLevel) {
    if(partSize<=0) {error="Part size must be positive.";return false;}
    QFile in(source);
    if(!in.open(QIODevice::ReadOnly)) {error=in.errorString();return false;}
    QDir dir(destination);
    if(!dir.exists() && !QDir().mkpath(destination)) {error="Cannot create output directory.";return false;}
    QString base=QFileInfo(source).fileName();
    if(!safeName(base)) {error="Invalid source filename.";return false;}
    QString manifestPath=dir.filePath(base+".yasmanifest.json");
    if(QFileInfo::exists(manifestPath)) {error="Manifest already exists. Choose another output directory.";return false;}
    if(compressionLevel<0 || compressionLevel>9) {error="Compression level must be 0..9.";return false;}
    if(compressionLevel>0) {
        const qint64 total=in.size();
        QCryptographicHash whole(QCryptographicHash::Sha256);
        QJsonArray parts;
        qint64 done=0;
        int index=0;
        while(done<total) {
            ++index;
            const QString name=QString("%1.part%2").arg(base).arg(index,6,10,QLatin1Char('0'));
            const QString path=dir.filePath(name);
            if(QFileInfo::exists(path)) {error="Output part already exists: "+name;return false;}
            QSaveFile out(path);
            if(!out.open(QIODevice::WriteOnly)) {error=out.errorString();return false;}
            QCryptographicHash partHash(QCryptographicHash::Sha256);
            QCryptographicHash rawHash(QCryptographicHash::Sha256);
            qint64 stored=0,raw=0;
            const qint64 target=std::min(partSize,total-done);
            while(raw<target) {
                if(progress && !progress(done,total)) {out.cancelWriting();error="Cancelled.";return false;}
                const QByteArray block=in.read(std::min(bufferSize,target-raw));
                if(block.isEmpty()) {out.cancelWriting();error="Source read failed or changed.";return false;}
                const QByteArray packed=qCompress(block,compressionLevel);
                if(packed.isEmpty() || packed.size()>bufferSize+4096) {out.cancelWriting();error="Compression failed.";return false;}
                const quint32 length=qToLittleEndian<quint32>(static_cast<quint32>(packed.size()));
                const QByteArray frame(reinterpret_cast<const char*>(&length),sizeof(length));
                if(!writeAll(out,frame) || !writeAll(out,packed)) {out.cancelWriting();error="Part write failed.";return false;}
                partHash.addData(frame);partHash.addData(packed);
                rawHash.addData(block);whole.addData(block);
                stored+=frame.size()+packed.size();raw+=block.size();done+=block.size();
            }
            if(!out.commit()) {error="Cannot commit compressed part.";return false;}
            QJsonObject part;
            part["name"]=name;part["size"]=QString::number(stored);
            part["rawSize"]=QString::number(raw);
            part["sha256"]=hashResult(partHash);
            part["rawSha256"]=hashResult(rawHash);
            parts.append(part);
        }
        if(in.size()!=total) {error="Source size changed.";return false;}
        QJsonObject meta;
        meta["format"]="YAS-SPLIT-2";meta["compression"]="zlib-chunked";
        meta["compressionLevel"]=compressionLevel;
        meta["originalName"]=base;meta["originalSize"]=QString::number(total);
        meta["sha256"]=hashResult(whole);meta["partSize"]=QString::number(partSize);
        meta["parts"]=parts;
        QSaveFile manifest(manifestPath);
        if(!manifest.open(QIODevice::WriteOnly)) {error=manifest.errorString();return false;}
        if(!writeAll(manifest,QJsonDocument(meta).toJson(QJsonDocument::Indented)) || !manifest.commit()) {
            error="Cannot write compressed manifest.";return false;
        }
        if(progress) progress(total,total);
        return true;
    }
    const qint64 total=in.size();
    QJsonArray parts;
    QCryptographicHash whole(QCryptographicHash::Sha256);
    qint64 done=0;
    int index=0;
    while(done<total) {
        ++index;
        QString name=QString("%1.part%2").arg(base).arg(index,6,10,QLatin1Char('0'));
        QString partPath=dir.filePath(name);
        if(QFileInfo::exists(partPath)) {error="Output part already exists: "+name;return false;}
        QSaveFile out(partPath);
        if(!out.open(QIODevice::WriteOnly)) {error=out.errorString();return false;}
        QCryptographicHash partHash(QCryptographicHash::Sha256);
        qint64 partWritten=0;
        const qint64 target=std::min(partSize,total-done);
        while(partWritten<target) {
            if(progress && !progress(done,total)) {out.cancelWriting();error="Cancelled.";return false;}
            QByteArray block=in.read(std::min(bufferSize,target-partWritten));
            if(block.isEmpty()) {out.cancelWriting();error="Source read failed or source changed.";return false;}
            if(!writeAll(out,block)) {out.cancelWriting();error="Part write failed.";return false;}
            partHash.addData(block);whole.addData(block);
            partWritten+=block.size();done+=block.size();
        }
        if(!out.commit()) {error="Cannot commit part: "+name;return false;}
        QJsonObject p; p["name"]=name;p["size"]=QString::number(partWritten);p["sha256"]=hashResult(partHash);
        parts.append(p);
    }
    if(in.size()!=total) {error="Source size changed during operation.";return false;}
    QJsonObject meta;
    meta["format"]="YAS-SPLIT-1";meta["originalName"]=base;
    meta["originalSize"]=QString::number(total);
    meta["sha256"]=hashResult(whole);
    meta["partSize"]=QString::number(partSize);
    meta["parts"]=parts;
    QSaveFile manifest(manifestPath);
    if(!manifest.open(QIODevice::WriteOnly)) {error=manifest.errorString();return false;}
    if(!writeAll(manifest,QJsonDocument(meta).toJson(QJsonDocument::Indented)) || !manifest.commit()) {
        error="Could not write manifest.";return false;
    }
    if(progress) progress(total,total);
    return true;
}
bool SplitEngine::join(const QString &manifestPath,const QString &destination,
                       const Progress &progress,QString &error) {
    QFile manifest(manifestPath);
    if(!manifest.open(QIODevice::ReadOnly)) {error=manifest.errorString();return false;}
    QJsonParseError parse;
    QJsonDocument doc=QJsonDocument::fromJson(manifest.readAll(),&parse);
    if(parse.error!=QJsonParseError::NoError || !doc.isObject()) {error="Invalid manifest JSON.";return false;}
    QJsonObject meta=doc.object();
    if(meta.value("format").toString()!="YAS-SPLIT-1" && meta.value("format").toString()!="YAS-SPLIT-2") {error="Unsupported manifest format.";return false;}
    bool ok=false;
    qint64 total=meta.value("originalSize").toString().toLongLong(&ok);
    if(!ok || total<0) {error="Invalid original size.";return false;}
    QString originalName=meta.value("originalName").toString();
    if(!safeName(originalName)) {error="Unsafe original filename.";return false;}
    QJsonArray parts=meta.value("parts").toArray();
    if((total>0 && parts.isEmpty()) || parts.size()>1000000) {error="Invalid part count.";return false;}
    QDir inputDir=QFileInfo(manifestPath).absoluteDir();
    QDir outputDir(destination);
    if(!outputDir.exists() && !QDir().mkpath(destination)) {error="Cannot create output directory.";return false;}
    QString target=outputDir.filePath(originalName);
    if(QFileInfo::exists(target)) {error="Output file already exists.";return false;}
    QSaveFile out(target);
    if(!out.open(QIODevice::WriteOnly)) {error=out.errorString();return false;}
    QCryptographicHash whole(QCryptographicHash::Sha256);
    qint64 done=0;
    if(meta.value("format").toString()=="YAS-SPLIT-2") {
        if(meta.value("compression").toString()!="zlib-chunked") {
            out.cancelWriting();error="Unsupported compression codec.";return false;
        }
        QSet<QString> names;
        for(const QJsonValue &v:parts) {
            if(!v.isObject()) {out.cancelWriting();error="Invalid part entry.";return false;}
            const QJsonObject p=v.toObject();
            const QString name=p.value("name").toString();
            if(!safeName(name) || names.contains(name)) {
                out.cancelWriting();error="Unsafe or duplicate part name.";return false;
            }
            names.insert(name);
            bool sizeOk=false,rawOk=false;
            const qint64 size=p.value("size").toString().toLongLong(&sizeOk);
            const qint64 rawSize=p.value("rawSize").toString().toLongLong(&rawOk);
            if(!sizeOk || !rawOk || size<0 || rawSize<=0 || rawSize>total-done) {
                out.cancelWriting();error="Invalid compressed part sizes.";return false;
            }
            QFile in(inputDir.filePath(name));
            if(!in.open(QIODevice::ReadOnly) || in.size()!=size) {
                out.cancelWriting();error="Compressed part missing or wrong size: "+name;return false;
            }
            QCryptographicHash packedHash(QCryptographicHash::Sha256);
            QCryptographicHash rawHash(QCryptographicHash::Sha256);
            qint64 remaining=size,restored=0;
            while(remaining>0) {
                if(progress && !progress(done,total)) {out.cancelWriting();error="Cancelled.";return false;}
                if(remaining<4) {out.cancelWriting();error="Truncated frame header.";return false;}
                const QByteArray header=in.read(4);
                if(header.size()!=4) {out.cancelWriting();error="Truncated frame header.";return false;}
                const quint32 compressedLength=qFromLittleEndian<quint32>(reinterpret_cast<const uchar*>(header.constData()));
                if(compressedLength<6 || compressedLength>static_cast<quint32>(bufferSize+4096) ||
                   compressedLength>static_cast<quint64>(remaining-4)) {
                    out.cancelWriting();error="Invalid compressed frame length.";return false;
                }
                QByteArray packed=in.read(compressedLength);
                if(packed.size()!=static_cast<qsizetype>(compressedLength)) {
                    out.cancelWriting();error="Truncated compressed frame.";return false;
                }
                // qCompress frames contain a four-byte uncompressed-size header.
                const quint32 decodedLength=qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(packed.constData()));
                if(decodedLength==0 || decodedLength>bufferSize ||
                   decodedLength>static_cast<quint64>(rawSize-restored)) {
                    out.cancelWriting();error="Compressed frame has invalid decoded size.";return false;
                }
                const QByteArray raw=qUncompress(packed);
                if(raw.size()!=static_cast<qsizetype>(decodedLength) || !writeAll(out,raw)) {
                    out.cancelWriting();error="Compressed part is damaged or output write failed.";return false;
                }
                packedHash.addData(header);packedHash.addData(packed);
                rawHash.addData(raw);whole.addData(raw);
                restored+=raw.size();done+=raw.size();remaining-=4+compressedLength;
            }
            if(restored!=rawSize || hashResult(rawHash).compare(p.value("rawSha256").toString(),Qt::CaseInsensitive)!=0 ||
               hashResult(packedHash).compare(p.value("sha256").toString(),Qt::CaseInsensitive)!=0) {
                out.cancelWriting();error="Compressed part checksum mismatch: "+name;return false;
            }
        }
        if(done!=total || hashResult(whole).compare(meta.value("sha256").toString(),Qt::CaseInsensitive)!=0) {
            out.cancelWriting();error="Original SHA-256 mismatch.";return false;
        }
        if(!out.commit()) {error="Cannot commit reconstructed file.";return false;}
        if(progress) progress(total,total);
        return true;
    }
    for(const QJsonValue &v:parts) {
        if(!v.isObject()) {out.cancelWriting();error="Invalid part record.";return false;}
        QJsonObject p=v.toObject();
        QString name=p.value("name").toString();
        if(!safeName(name)) {out.cancelWriting();error="Unsafe part filename.";return false;}
        qint64 expected=p.value("size").toString().toLongLong(&ok);
        if(!ok || expected<0 || expected>total-done) {out.cancelWriting();error="Invalid part size.";return false;}
        QFile in(inputDir.filePath(name));
        if(!in.open(QIODevice::ReadOnly) || in.size()!=expected) {
            out.cancelWriting();error="Missing or invalid part: "+name;return false;
        }
        QCryptographicHash partHash(QCryptographicHash::Sha256);
        qint64 readCount=0;
        while(readCount<expected) {
            if(progress && !progress(done,total)) {out.cancelWriting();error="Cancelled.";return false;}
            QByteArray block=in.read(std::min(bufferSize,expected-readCount));
            if(block.isEmpty() || !writeAll(out,block)) {
                out.cancelWriting();error="Read/write error in: "+name;return false;
            }
            partHash.addData(block);whole.addData(block);
            readCount+=block.size();done+=block.size();
        }
        if(hashResult(partHash).compare(p.value("sha256").toString(),Qt::CaseInsensitive)!=0) {
            out.cancelWriting();error="Part hash mismatch: "+name;return false;
        }
    }
    if(done!=total || hashResult(whole).compare(meta.value("sha256").toString(),Qt::CaseInsensitive)!=0) {
        out.cancelWriting();error="Original file checksum mismatch.";return false;
    }
    if(!out.commit()) {error="Cannot commit reconstructed file.";return false;}
    if(progress) progress(total,total);
    return true;
}
