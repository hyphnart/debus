#include "AnalysisEngine.h"
#include <QFile>
#include <QFileInfo>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
namespace {
struct Signature { const char *name; const char *magic; int size; int offset; };
constexpr Signature signatures[]={
    {"Windows PE (MZ)","MZ",2,0},
    {"ELF executable","\x7f""ELF",4,0},
    {"PDF document","%PDF-",5,0},
    {"ZIP container","PK\x03\x04",4,0},
    {"7-Zip archive","7z\xbc\xaf\x27\x1c",6,0},
    {"PNG image","\x89PNG\r\n\x1a\n",8,0},
    {"JPEG image","\xff\xd8\xff",3,0},
    {"GIF image","GIF8",4,0},
    {"SQLite database","SQLite format 3\0",16,0},
    {"GZIP stream","\x1f\x8b",2,0},
    {"RAR archive","Rar!\x1a\x07",6,0},
    {"RIFF container","RIFF",4,0},
    {"MP4/ISO BMFF","ftyp",4,4}
};
double entropyOf(const QByteArray &bytes) {
    if(bytes.isEmpty()) return 0;
    std::array<quint64,256> counts{};
    for(char c:bytes) ++counts[static_cast<unsigned char>(c)];
    double entropy=0;
    for(quint64 count:counts) if(count) {
        double p=static_cast<double>(count)/bytes.size();
        entropy-=p*std::log2(p);
    }
    return entropy;
}
}
AnalysisReport AnalysisEngine::analyze(const QString &path,Progress progress) {
    AnalysisReport result;
    QFile file(path);
    if(!file.open(QIODevice::ReadOnly)) {result.error=file.errorString();return result;}
    result.fileSize=file.size();
    QByteArray head=file.peek(64);
    result.fileType="Unknown binary";
    for(const auto &s:signatures) {
        if(head.size()>=s.offset+s.size && std::memcmp(head.constData()+s.offset,s.magic,s.size)==0) {
            result.fileType=QString::fromLatin1(s.name);
            result.signature=QString::fromLatin1(head.mid(s.offset,s.size).toHex(' ').toUpper());
            break;
        }
    }
    // Bounded-memory streaming analysis. Strings are capped to avoid huge UI models.
    constexpr qint64 blockSize=256*1024;
    constexpr int maxStrings=10000;
    constexpr int maxStringLength=512;
    QByteArray ascii;
    qint64 asciiStart=0;
    qint64 offset=0;
    auto flush=[&](){
        if(ascii.size()>=5 && result.strings.size()<maxStrings) {
            ExtractedString s; s.offset=asciiStart;s.encoding="ASCII";
            s.value=QString::fromLatin1(ascii);result.strings.append(s);
        }
        ascii.clear();
    };
    while(offset<result.fileSize) {
        if(progress && !progress(offset,result.fileSize)) {
            result.cancelled=true;result.error="Analysis cancelled.";return result;
        }
        QByteArray block=file.read(std::min(blockSize,result.fileSize-offset));
        if(block.isEmpty()) {result.error="Unexpected end of file or read failure.";return result;}
        result.entropy.append({offset,block.size(),entropyOf(block)});
        for(qsizetype i=0;i<block.size();++i) {
            unsigned char c=static_cast<unsigned char>(block.at(i));
            if(c>=32 && c<=126) {
                if(ascii.isEmpty()) asciiStart=offset+i;
                if(ascii.size()<maxStringLength) ascii.append(static_cast<char>(c));
            } else flush();
        }
        offset+=block.size();
    }
    flush();
    // Detect aligned UTF-16LE printable ASCII subset, including across chunk boundaries.
    // This is deliberately conservative: non-Latin Unicode text is not decoded yet.
    if(result.strings.size()<maxStrings && file.seek(0)) {
        QByteArray pending;
        QByteArray utf;
        qint64 utfStart=0;
        qint64 byteOffset=0;
        while(byteOffset<result.fileSize && result.strings.size()<maxStrings) {
            if(progress && !progress(byteOffset,result.fileSize)) {
                result.cancelled=true;result.error="Analysis cancelled.";return result;
            }
            QByteArray block=file.read(std::min(blockSize,result.fileSize-byteOffset));
            if(block.isEmpty()) {result.error="UTF-16 scan read failed.";return result;}
            QByteArray data=pending+block;
            qint64 base=byteOffset-pending.size();
            qsizetype i=0;
            for(;i+1<data.size();i+=2) {
                const unsigned char lo=static_cast<unsigned char>(data[i]);
                const unsigned char hi=static_cast<unsigned char>(data[i+1]);
                if(hi==0 && lo>=32 && lo<=126) {
                    if(utf.isEmpty()) utfStart=base+i;
                    if(utf.size()<maxStringLength) utf.append(static_cast<char>(lo));
                } else {
                    if(utf.size()>=5 && result.strings.size()<maxStrings) {
                        ExtractedString st;st.offset=utfStart;st.encoding="UTF-16LE";
                        st.value=QString::fromLatin1(utf);result.strings.append(st);
                    }
                    utf.clear();
                }
            }
            pending=data.mid(i);
            byteOffset+=block.size();
        }
        if(utf.size()>=5 && result.strings.size()<maxStrings) {
            ExtractedString st;st.offset=utfStart;st.encoding="UTF-16LE";
            st.value=QString::fromLatin1(utf);result.strings.append(st);
        }
    }
    if(progress) progress(result.fileSize,result.fileSize);
    return result;
}
