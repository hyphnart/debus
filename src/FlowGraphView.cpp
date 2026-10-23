#include "FlowGraphView.h"
#include <QGraphicsScene>
#include <QSettings>
#include <QGraphicsRectItem>
#include <QGraphicsTextItem>
#include <QGraphicsLineItem>
#include <QWheelEvent>
#include <QPen>
#include <QBrush>
#include <QFont>
#include <QMap>
#include <QPainter>
#include <QScrollBar>
#include <algorithm>
#include <cmath>
#include <functional>
#include <QGraphicsSceneMouseEvent>
namespace {
class BlockItem final : public QGraphicsRectItem {
public:
    BlockItem(quint64 address,const QRectF &rect,std::function<void(quint64)> open)
        :QGraphicsRectItem(rect),address_(address),open_(std::move(open)) {
        setCursor(Qt::PointingHandCursor);
        setZValue(2);
    }
protected:
    void mouseDoubleClickEvent(QGraphicsSceneMouseEvent *event) override {
        open_(address_);
        QGraphicsRectItem::mouseDoubleClickEvent(event);
    }
private:
    quint64 address_;
    std::function<void(quint64)> open_;
};
}
FlowGraphView::FlowGraphView(QWidget *parent):QGraphicsView(parent),scene_(new QGraphicsScene(this)) {
    setScene(scene_);
    setRenderHint(QPainter::Antialiasing,true);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setBackgroundBrush(QColor("#05070d"));
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
}
void FlowGraphView::wheelEvent(QWheelEvent *event) {
    if(event->modifiers() & Qt::ControlModifier) {
        const double factor=event->angleDelta().y()>0?1.12:1.0/1.12;
        const double current=transform().m11();
        if(current*factor>=0.3 && current*factor<=3.0)scale(factor,factor);
        event->accept();
    } else QGraphicsView::wheelEvent(event);
}
void FlowGraphView::refreshTheme() {
    setReport(lastReport_);
}
void FlowGraphView::setReport(const FlowReport &report) {
    const FlowReport snapshot=report;
    lastReport_=snapshot;
    const bool dark=QSettings("YAS","BinaryLabX").value("appearance/dark",true).toBool();
    const QColor bg=dark?QColor("#05070d"):QColor("#f3f6fb");
    const QColor boxColor=dark?QColor("#101b30"):QColor("#ffffff");
    const QColor fg=dark?QColor("#e2e8f0"):QColor("#1d293b");
    const QColor edgeText=dark?QColor("#cbd5e1"):QColor("#475569");
    setBackgroundBrush(bg);
    scene_->clear();
    constexpr qreal width=236.0,height=68.0,xgap=105.0,ygap=90.0;
    QMap<quint64,QPointF> positions;
    const int blockCount=static_cast<int>(snapshot.blocks.size());
    const int columns=std::clamp(static_cast<int>(std::sqrt(static_cast<double>(std::max(1,blockCount)))),1,5);
    for(int i=0;i<snapshot.blocks.size();++i) {
        const auto &block=snapshot.blocks[i];
        const qreal x=(i%columns)*(width+xgap);
        const qreal y=(i/columns)*(height+ygap);
        positions.insert(block.start,QPointF(x,y));
    }
    // Render edges first so nodes remain legible and clickable.
    for(const auto &edge:snapshot.edges) {
        if(!positions.contains(edge.from) || !positions.contains(edge.to))continue;
        const QPointF from=positions.value(edge.from)+QPointF(width/2,height);
        const QPointF to=positions.value(edge.to)+QPointF(width/2,0);
        QPen pen(edge.kind=="conditional"?QColor("#f59e0b"):QColor("#38bdf8"),2);
        pen.setCosmetic(true);
        scene_->addLine(QLineF(from,to),pen)->setZValue(0);
        const QPointF mid=(from+to)/2;
        auto *label=scene_->addText(edge.kind);
        label->setDefaultTextColor(edgeText);
        label->setPos(mid+QPointF(4,-22));
        label->setZValue(1);
    }
    for(const auto &block:snapshot.blocks) {
        const QPointF pos=positions.value(block.start);
        auto *node=new BlockItem(block.start,QRectF(pos,QSizeF(width,height)),
            [this](quint64 address){emit addressActivated(address);});
        node->setPen(QPen(QColor("#60a5fa"),1.5));
        node->setBrush(QBrush(boxColor));
        scene_->addItem(node);
        auto *label=scene_->addText(QString("BLOCK  0x%1\nInstructions: %2")
            .arg(block.start,0,16)
            .arg(block.lastInstruction-block.firstInstruction+1));
        label->setDefaultTextColor(fg);
        label->setFont(QFont("Consolas",10));
        label->setPos(pos+QPointF(12,10));
        label->setAcceptedMouseButtons(Qt::NoButton);
        label->setZValue(3);
    }
    scene_->setSceneRect(scene_->itemsBoundingRect().adjusted(-35,-35,35,35));
    resetTransform();
}
