#pragma once
#include <QFile>
#include <QByteArray>
#include <QString>
#include <memory>
class BinaryFile {
public:
    bool open(const QString &path);
    void close();
    qint64 size() const;
    QString path() const;
    QByteArray read(qint64 offset, qint64 length);
    QString sha256(QString *error = nullptr);
private:
    QFile file_;
};
