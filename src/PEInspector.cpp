#include "PEInspector.h"
#include <QFile>
#include <QByteArray>
#include <QtEndian>
#include <algorithm>
namespace {
bool u16(const QByteArray &b,qsizetype o,quint16 &v) {
    if(o<0 || o>b.size()-2) return false;
    v=qFromLittleEndian<quint16>(reinterpret_cast<const uchar*>(b.constData()+o));return true;
}
bool u32(const QByteArray &b,qsizetype o,quint32 &v) {
    if(o<0 || o>b.size()-4) return false;
    v=qFromLittleEndian<quint32>(reinterpret_cast<const uchar*>(b.constData()+o));return true;
}
bool u64(const QByteArray &b,qsizetype o,quint64 &v) {
    if(o<0 || o>b.size()-8) return false;
    v=qFromLittleEndian<quint64>(reinterpret_cast<const uchar*>(b.constData()+o));return true;
}
}
PEReport PEInspector::inspect(const QString &path) {
    PEReport r;
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)) {r.error=f.errorString();return r;}
    if(f.size()<64) {r.error="File is too small for DOS header.";return r;}
    QByteArray dos=f.read(64);
    quint32 peOffset=0;
    if(!dos.startsWith("MZ") || !u32(dos,0x3c,peOffset)) {r.error="Missing DOS header.";return r;}
    if(static_cast<quint64>(peOffset)+24>static_cast<quint64>(f.size())) {
        r.error="Invalid PE header offset.";return r;
    }
    if(!f.seek(peOffset)) {r.error="Cannot seek PE header.";return r;}
    QByteArray header=f.read(24);
    if(header.size()!=24 || header.left(4)!=QByteArray("PE\0\0",4)) {
        r.error="Missing PE signature.";return r;
    }
    quint16 optionalSize=0;
    u16(header,4,r.machine);
    u16(header,6,r.sectionCount);
    u16(header,20,optionalSize);
    if(r.sectionCount>96 || optionalSize<24 ||
       static_cast<quint64>(peOffset)+24+optionalSize+
       static_cast<quint64>(r.sectionCount)*40>static_cast<quint64>(f.size())) {
        r.error="Invalid optional header or section table.";return r;
    }
    QByteArray opt=f.read(optionalSize);
    quint16 magic=0;
    if(!u16(opt,0,magic) || (magic!=0x10b && magic!=0x20b)) {
        r.error="Unsupported PE optional header.";return r;
    }
    if(!u32(opt,16,r.entryPointRva)) {r.error="Truncated entry point.";return r;}
    if(magic==0x20b) {
        if(!u64(opt,24,r.imageBase)) {r.error="Truncated image base.";return r;}
    } else {
        quint32 base=0;
        if(!u32(opt,28,base)) {r.error="Truncated image base.";return r;}
        r.imageBase=base;
    }
    switch(r.machine) {
        case 0x14c:r.architecture="x86";break;
        case 0x8664:r.architecture="x86-64";break;
        case 0xaa64:r.architecture="ARM64";break;
        default:r.architecture=QString("Machine 0x%1").arg(r.machine,4,16,QLatin1Char('0'));break;
    }
    for(int i=0;i<r.sectionCount;++i) {
        QByteArray b=f.read(40);
        if(b.size()!=40) {r.error="Truncated section table.";r.sections.clear();return r;}
        PESection s;
        QByteArray name=b.left(8);
        int nullPos=name.indexOf('\0');
        if(nullPos>=0) name.truncate(nullPos);
        s.name=QString::fromLatin1(name);
        u32(b,8,s.virtualSize);u32(b,12,s.virtualAddress);
        u32(b,16,s.rawSize);u32(b,20,s.rawOffset);
        if(static_cast<quint64>(s.rawOffset)+s.rawSize>static_cast<quint64>(f.size()) && s.rawSize) {
            r.error="Section extends beyond file.";r.sections.clear();return r;
        }
        r.sections.append(s);
    }
    // Import directory (data directory index 1); use RVA->file offset mapping.
    const qsizetype dirOffset=(magic==0x20b)?112:96;
    quint32 importRva=0, importSize=0;
    if(opt.size()>=dirOffset+16) {
        u32(opt,dirOffset+8,importRva);
        u32(opt,dirOffset+12,importSize);
    }
    auto mapRva=[&](quint32 rva,quint64 count,quint64 &fileOffset)->bool {
        for(const auto &sec:r.sections) {
            const quint64 begin=sec.virtualAddress;
            const quint64 end=begin+sec.rawSize;
            if(rva>=begin && static_cast<quint64>(rva)<end && count<=end-rva) {
                fileOffset=static_cast<quint64>(sec.rawOffset)+(rva-begin);
                return fileOffset<=static_cast<quint64>(f.size()) && count<=static_cast<quint64>(f.size())-fileOffset;
            }
        }
        return false;
    };
    auto readAt=[&](quint64 offset,qint64 length)->QByteArray {
        if(offset>static_cast<quint64>(f.size()) || static_cast<quint64>(length)>static_cast<quint64>(f.size())-offset) return {};
        if(!f.seek(static_cast<qint64>(offset))) return {};
        return f.read(length);
    };
    auto readCString=[&](quint32 rva)->QString {
        quint64 offset=0;
        if(!mapRva(rva,1,offset)) return {};
        QByteArray b=readAt(offset,std::min<qint64>(512,f.size()-static_cast<qint64>(offset)));
        int end=b.indexOf('\0');
        if(end<0) return {};
        return QString::fromLatin1(b.left(end));
    };
    if(importRva && importSize) {
        quint64 importsOffset=0;
        if(!mapRva(importRva,20,importsOffset)) r.importWarning="Import directory is not file-backed.";
        else {
            constexpr int maxDlls=512, maxSymbols=10000;
            int totalSymbols=0;
            for(int i=0;i<maxDlls;++i) {
                quint64 descriptor=importsOffset+static_cast<quint64>(i)*20;
                QByteArray b=readAt(descriptor,20);
                quint32 originalThunk=0,nameRva=0,firstThunk=0;
                if(b.size()!=20 || !u32(b,0,originalThunk) || !u32(b,12,nameRva) || !u32(b,16,firstThunk)) {
                    r.importWarning="Truncated import directory.";break;
                }
                if(originalThunk==0 && nameRva==0 && firstThunk==0) break;
                PEImport imp; imp.dll=readCString(nameRva);
                if(imp.dll.isEmpty()) {r.importWarning="Invalid imported DLL name.";break;}
                quint32 thunkRva=originalThunk?originalThunk:firstThunk;
                const int width=magic==0x20b?8:4;
                for(int j=0;j<maxSymbols && totalSymbols<maxSymbols;++j) {
                    quint64 thunkOffset=0;
                    const quint64 thunkAddress=static_cast<quint64>(thunkRva)+static_cast<quint64>(j)*width;
                    if(thunkAddress>0xffffffffULL || !mapRva(static_cast<quint32>(thunkAddress),width,thunkOffset)) {
                        r.importWarning="Import thunk outside file-backed sections.";break;
                    }
                    QByteArray entry=readAt(thunkOffset,width);
                    quint64 value=0;
                    if(width==8) {if(!u64(entry,0,value)) break;}
                    else {quint32 tmp=0;if(!u32(entry,0,tmp)) break;value=tmp;}
                    if(!value) break;
                    quint64 ordinalMask=width==8?0x8000000000000000ULL:0x80000000ULL;
                    if(value & ordinalMask) imp.functions.append(QString("Ordinal #%1").arg(value&0xffff));
                    else if(value<=0xffffffffULL) {
                        QString symbol=readCString(static_cast<quint32>(value)+2);
                        imp.functions.append(symbol.isEmpty()?"<invalid symbol>":symbol);
                    } else imp.functions.append("<invalid thunk>");
                    ++totalSymbols;
                }
                r.imports.append(imp);
                if(totalSymbols>=maxSymbols) {r.importWarning="Import symbol limit reached.";break;}
            }
        }
    }
    r.valid=true;
    return r;
}

bool PEInspector::rvaToFileOffset(const PEReport &report,quint32 rva,quint64 fileSize,quint64 &offset) {
    if(!report.valid) return false;
    for(const PESection &s:report.sections) {
        const quint64 start=s.virtualAddress;
        const quint64 delta=static_cast<quint64>(rva)>=start ? static_cast<quint64>(rva)-start : UINT64_MAX;
        // Only bytes backed by actual file data are safe to disassemble.
        if(delta>=s.rawSize) continue;
        const quint64 physical=static_cast<quint64>(s.rawOffset)+delta;
        if(physical>=fileSize) return false;
        offset=physical;
        return true;
    }
    return false;
}
