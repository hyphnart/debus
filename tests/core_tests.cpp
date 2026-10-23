#include "SplitEngine.h"
#include "DiffEngine.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QCryptographicHash>
#include <cstdlib>
static void require(bool pass,const char *message) {
    if(!pass) {qCritical()<<"FAIL:"<<message;std::exit(1);}
}
static QByteArray contents(const QString &path) {
    QFile file(path);
    require(file.open(QIODevice::ReadOnly),"open test file");
    return file.readAll();
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    QTemporaryDir temp;
    require(temp.isValid(),"create temporary directory");
    const QString input=temp.filePath("sample.bin");
    QByteArray data;
    for(int i=0;i<300001;++i) data.append(static_cast<char>(i%251));
    {
        QFile file(input);
        require(file.open(QIODevice::WriteOnly),"create input");
        require(file.write(data)==data.size(),"write input");
    }
    const QString parts=temp.filePath("parts");
    QString error;
    require(SplitEngine::split(input,parts,65536,{},error),"split file");
    const QString manifest=QDir(parts).filePath("sample.bin.yasmanifest.json");
    require(QFile::exists(manifest),"manifest created");
    const QString rebuilt=temp.filePath("rebuilt");
    require(SplitEngine::join(manifest,rebuilt,{},error),"join file");
    const QString output=QDir(rebuilt).filePath("sample.bin");
    require(contents(output)==data,"byte-for-byte reconstruction");
    DiffReport identical=DiffEngine::compare(input,output);
    require(identical.error.isEmpty() && identical.changedBytes==0,"identical diff");
    {
        QFile file(output);
        require(file.open(QIODevice::ReadWrite),"open rebuilt file for mutation");
        require(file.seek(12345),"seek");
        require(file.write("X",1)==1,"mutate");
    }
    DiffReport changed=DiffEngine::compare(input,output);
    require(changed.error.isEmpty() && changed.changedBytes==1,"one-byte diff");
    // Empty file round trip.
    const QString empty=temp.filePath("empty.bin");
    {QFile file(empty);require(file.open(QIODevice::WriteOnly),"create empty file");}
    const QString emptyParts=temp.filePath("empty-parts");
    require(SplitEngine::split(empty,emptyParts,64,{},error),"split empty");
    require(SplitEngine::join(QDir(emptyParts).filePath("empty.bin.yasmanifest.json"),
        temp.filePath("empty-rebuilt"),{},error),"join empty");
    require(contents(temp.filePath("empty-rebuilt/empty.bin")).isEmpty(),"empty output");
    // New YAS-SPLIT-2: lossless compression and automatic format detection.
    const QString compressedParts=temp.filePath("compressed-parts");
    const QString repeated=temp.filePath("repeated.bin");
    QByteArray repeatedData(512*1024,'A');
    { QFile file(repeated);require(file.open(QIODevice::WriteOnly),"create compressible file");
      require(file.write(repeatedData)==repeatedData.size(),"write compressible file"); }
    require(SplitEngine::split(repeated,compressedParts,65536,{},error,6),"compressed split");
    const QString packedManifest=QDir(compressedParts).filePath("repeated.bin.yasmanifest.json");
    const QString packedPart=QDir(compressedParts).filePath("repeated.bin.part000001");
    require(QFileInfo(packedPart).size()<65536,"compression reduces repetitive data");
    const QString packedResult=temp.filePath("compressed-rebuilt");
    require(SplitEngine::join(packedManifest,packedResult,{},error),"compressed join");
    require(contents(QDir(packedResult).filePath("repeated.bin"))==repeatedData,"compressed roundtrip exact");
    // Corrupted compressed input must be rejected (both packed and original hashes verified).
    { QFile broken(packedPart);require(broken.open(QIODevice::ReadWrite),"open compressed part");
      require(broken.seek(12),"seek compressed part");
      require(broken.write("Z",1)==1,"corrupt part"); }
    require(!SplitEngine::join(packedManifest,temp.filePath("broken-out"),{},error),"detect damaged part");
    const QString compressedEmpty=temp.filePath("compressed-empty");
    require(SplitEngine::split(empty,compressedEmpty,65536,{},error,6),"split empty compressed");
    require(SplitEngine::join(QDir(compressedEmpty).filePath("empty.bin.yasmanifest.json"),
        temp.filePath("compressed-empty-rebuilt"),{},error),"join empty compressed");
    require(contents(temp.filePath("compressed-empty-rebuilt/empty.bin")).isEmpty(),"empty compressed output");
    qInfo()<<"PASS: split, rebuild, diff, empty file";
    return 0;
}
