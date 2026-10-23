#include "HexView.h"
#include <QPainter>
#include <QSettings>
#include <QClipboard>
#include <QApplication>
#include <QMouseEvent>
#include <QPoint>
#include <QScrollBar>
#include <QWheelEvent>
#include <QKeyEvent>
#include <QFontDatabase>
#include <algorithm>
#include <limits>
HexView::HexView(QWidget *parent):QAbstractScrollArea(parent) {
    setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    QFont f=font(); f.setPointSize(10); setFont(f);
    setFocusPolicy(Qt::StrongFocus);
    setFrameShape(QFrame::NoFrame);
    connect(verticalScrollBar(), &QScrollBar::valueChanged, this, [this](int v) {
        if(!doc_) return;
        const qint64 totalLines=(doc_->size()+15)/16;
        const qint64 maxLine=std::max<qint64>(0,totalLines-visibleLines_);
        const qint64 scale=std::min<qint64>(1000000,maxLine);
        offset_=(scale ? static_cast<qint64>(static_cast<long double>(maxLine)*v/scale) : 0)*16;
        viewport()->update();
    });
}
void HexView::setDocument(std::shared_ptr<BinaryFile> d) {
    doc_=std::move(d); offset_=0; selectionAnchor_=-1; selectionStart_=-1; selectionEnd_=-1; syncScrollbar(); viewport()->update();
}
void HexView::resizeEvent(QResizeEvent *e) {
    QAbstractScrollArea::resizeEvent(e);
    lineHeight_=std::max(15,QFontMetrics(font()).height()+5);
    visibleLines_=std::max(1,viewport()->height()/lineHeight_);
    syncScrollbar();
}
void HexView::syncScrollbar() {
    if(!doc_ || doc_->size()==0) { verticalScrollBar()->setRange(0,0); return; }
    qint64 totalLines=(doc_->size()+15)/16;
    qint64 maxLine=std::max<qint64>(0,totalLines-visibleLines_);
    verticalScrollBar()->blockSignals(true);
    const qint64 scale=std::min<qint64>(1000000,maxLine);
    verticalScrollBar()->setRange(0, static_cast<int>(scale));
    verticalScrollBar()->setPageStep(std::max(1,static_cast<int>(static_cast<long double>(scale)*visibleLines_/std::max<qint64>(1,totalLines))));
    verticalScrollBar()->setValue(maxLine ? static_cast<int>(std::min<long double>(scale,static_cast<long double>(offset_/16)*scale/maxLine)):0);
    verticalScrollBar()->blockSignals(false);
}
void HexView::jumpTo(qint64 offset) {
    if(!doc_ || doc_->size()==0) return;
    offset_=std::clamp<qint64>(offset,0,doc_->size()-1)/16*16;
    syncScrollbar(); viewport()->update();
}
void HexView::moveLines(qint64 lines) {
    if(!doc_) return;
    const qint64 current=offset_/16;
    const qint64 maxLine=std::max<qint64>(0,(doc_->size()+15)/16-visibleLines_);
    jumpTo(std::clamp<qint64>(current+lines,0,maxLine)*16);
}
void HexView::wheelEvent(QWheelEvent *e) {
    moveLines(-e->angleDelta().y()/120*3); e->accept();
}
void HexView::keyPressEvent(QKeyEvent *e) {
    if(e->key()==Qt::Key_Down) moveLines(1);
    else if(e->key()==Qt::Key_Up) moveLines(-1);
    else if(e->key()==Qt::Key_PageDown) moveLines(visibleLines_);
    else if(e->key()==Qt::Key_PageUp) moveLines(-visibleLines_);
    else if(e->matches(QKeySequence::Copy)) copySelectedHex();
    else QAbstractScrollArea::keyPressEvent(e);
}
void HexView::paintEvent(QPaintEvent *) {
    QPainter p(viewport());
    const bool dark=QSettings("YAS","BinaryLabX").value("appearance/dark",true).toBool();
    p.fillRect(viewport()->rect(),dark?QColor("#080f1c"):QColor("#ffffff"));
    if(!doc_) { p.setPen(QColor("#94a3b8")); p.drawText(24,40,"Open a file to inspect its bytes"); return; }
    QFontMetrics fm(font());
    int charW=fm.horizontalAdvance(QLatin1Char('0'));
    int x0=16, hexX=x0+19*charW, asciiX=hexX+50*charW;
    p.setPen((dark?QColor("#8aa1bb"):QColor("#475569")));
    p.drawText(x0, lineHeight_, "OFFSET");
    p.drawText(hexX, lineHeight_, "HEX BYTES");
    p.drawText(asciiX, lineHeight_, "ASCII");
    QByteArray bytes=doc_->read(offset_,static_cast<qint64>(visibleLines_)*16);
    for(int row=0;row<visibleLines_;++row) {
        int start=row*16;
        if(start>=bytes.size()) break;
        qint64 absolute=offset_+start;
        int y=(row+2)*lineHeight_;
        p.setPen((dark?QColor("#75aaff"):QColor("#1d4ed8")));
        p.drawText(x0,y,QString("%1").arg(static_cast<qulonglong>(absolute),16,16,QLatin1Char('0')).toUpper());
        QString hex,ascii;
        for(int col=0;col<16 && start+col<bytes.size();++col) {
            unsigned char b=static_cast<unsigned char>(bytes[start+col]);
            hex+=QString("%1 ").arg(b,2,16,QLatin1Char('0')).toUpper();
            ascii+=b>=32 && b<=126 ? QChar(b) : QChar('.');
        }
        if(selectionStart_>=0) {
            for(int col=0;col<16 && start+col<bytes.size();++col) {
                const qint64 pos=absolute+col;
                if(pos>=selectionStart_ && pos<selectionEnd_) {
                    p.fillRect(hexX+col*3*charW,y-fm.ascent(),3*charW,lineHeight_,(dark?QColor("#23558a"):QColor("#bfdbfe")));
                    p.fillRect(asciiX+col*charW,y-fm.ascent(),charW,lineHeight_,(dark?QColor("#23558a"):QColor("#bfdbfe")));
                }
            }
        }
        p.setPen(dark?QColor("#dce7f6"):QColor("#172338")); p.drawText(hexX,y,hex);
        p.setPen(dark?QColor("#4adea7"):QColor("#047857")); p.drawText(asciiX,y,ascii);
    }
}

qint64 HexView::byteAt(const QPoint &position) const {
    if(!doc_ || doc_->size()<=0)return -1;
    const QFontMetrics fm(font());
    const int cw=fm.horizontalAdvance(QLatin1Char('0'));
    const int hexX=16+19*cw;
    const int asciiX=hexX+50*cw;
    const int row=position.y()/lineHeight_-1;
    if(row<0 || row>=visibleLines_)return -1;
    int column=-1;
    if(position.x()>=hexX && position.x()<hexX+48*cw)
        column=(position.x()-hexX)/(3*cw);
    else if(position.x()>=asciiX && position.x()<asciiX+16*cw)
        column=(position.x()-asciiX)/cw;
    if(column<0 || column>=16)return -1;
    const qint64 byte=offset_+static_cast<qint64>(row)*16+column;
    return byte<doc_->size()?byte:-1;
}
void HexView::setSelection(qint64 first,qint64 last) {
    if(!doc_ || first<0 || last<0)return;
    selectionStart_=std::min(first,last);
    selectionEnd_=std::min(doc_->size(),std::max(first,last)+1);
    viewport()->update();
}
void HexView::mousePressEvent(QMouseEvent *event) {
    if(event->button()==Qt::LeftButton) {
        const qint64 at=byteAt(event->pos());
        if(at>=0){selectionAnchor_=at;setSelection(at,at);event->accept();return;}
    }
    QAbstractScrollArea::mousePressEvent(event);
}
void HexView::mouseMoveEvent(QMouseEvent *event) {
    if((event->buttons()&Qt::LeftButton) && selectionAnchor_>=0) {
        const qint64 at=byteAt(event->pos());
        if(at>=0){setSelection(selectionAnchor_,at);event->accept();return;}
    }
    QAbstractScrollArea::mouseMoveEvent(event);
}
void HexView::mouseReleaseEvent(QMouseEvent *event) {
    if(event->button()==Qt::LeftButton)selectionAnchor_=-1;
    QAbstractScrollArea::mouseReleaseEvent(event);
}
QByteArray HexView::selectedBytes() const {
    if(!hasSelection() || !doc_)return {};
    // Hard limit avoids unexpectedly copying gigabytes into the clipboard.
    constexpr qint64 maxCopy=16*1024*1024;
    return doc_->read(selectionStart_,std::min(selectionEnd_-selectionStart_,maxCopy));
}
void HexView::copySelectedHex() {
    if(!hasSelection())return;
    const QByteArray bytes=selectedBytes();
    QStringList values;
    values.reserve(bytes.size());
    for(unsigned char b:bytes)values.append(QString("%1").arg(b,2,16,QLatin1Char('0')).toUpper());
    QApplication::clipboard()->setText(values.join(' '));
}
void HexView::copySelectedAscii() {
    if(!hasSelection())return;
    const QByteArray bytes=selectedBytes();
    QString result;result.reserve(bytes.size());
    for(unsigned char b:bytes)result.append(b>=32&&b<=126?QChar(b):QChar('.'));
    QApplication::clipboard()->setText(result);
}
