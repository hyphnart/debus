#include "BinaryFile.h"
#include <QCryptographicHash>
#include <algorithm>
bool BinaryFile::open(const QString &path) {
    close();
    file_.setFileName(path);
    return file_.open(QIODevice::ReadOnly);
}
void BinaryFile::close() { if (file_.isOpen()) file_.close(); }
qint64 BinaryFile::size() const { return file_.isOpen() ? file_.size() : 0; }
QString BinaryFile::path() const { return file_.fileName(); }
QByteArray BinaryFile::read(qint64 offset, qint64 length) {
    if (!file_.isOpen() || offset < 0 || length <= 0 || offset >= size()) return {};
    if (!file_.seek(offset)) return {};
    return file_.read(std::min(length, size()-offset));
}
QString BinaryFile::sha256(QString *error) {
    if (!file_.isOpen()) { if(error) *error="No file open"; return {}; }
    if (!file_.seek(0)) { if(error) *error="Cannot seek file"; return {}; }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file_.atEnd()) {
        QByteArray block=file_.read(1024*1024);
        if (block.isEmpty() && file_.error()!=QFileDevice::NoError) {
            if(error) *error=file_.errorString();
            return {};
        }
        if (!block.isEmpty()) hash.addData(block);
    }
    return QString::fromLatin1(hash.result().toHex());
}
