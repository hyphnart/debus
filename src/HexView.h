#pragma once
#include <QAbstractScrollArea>
#include <QFont>
#include <memory>
#include "BinaryFile.h"
class HexView : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit HexView(QWidget *parent=nullptr);
    void setDocument(std::shared_ptr<BinaryFile> document);
    void jumpTo(qint64 offset);
    qint64 currentOffset() const { return offset_; }
    QByteArray selectedBytes() const;
    bool hasSelection() const { return selectionStart_>=0 && selectionEnd_>selectionStart_; }
    void copySelectedHex();
    void copySelectedAscii();
protected:
    void paintEvent(QPaintEvent *) override;
    void resizeEvent(QResizeEvent *) override;
    void wheelEvent(QWheelEvent *) override;
    void keyPressEvent(QKeyEvent *) override;
    void mousePressEvent(QMouseEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;
    void mouseReleaseEvent(QMouseEvent *) override;
private:
    void syncScrollbar();
    void moveLines(qint64 lines);
    std::shared_ptr<BinaryFile> doc_;
    qint64 offset_=0;
    qint64 selectionAnchor_=-1;
    qint64 selectionStart_=-1;
    qint64 selectionEnd_=-1;
    qint64 byteAt(const QPoint &position) const;
    void setSelection(qint64 first,qint64 last);
    int lineHeight_=19;
    int visibleLines_=1;
};
