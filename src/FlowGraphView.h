#pragma once
#include <QGraphicsView>
#include "ControlFlowEngine.h"
class QGraphicsScene;
class QWheelEvent;
class FlowGraphView : public QGraphicsView {
    Q_OBJECT
public:
    explicit FlowGraphView(QWidget *parent=nullptr);
    void setReport(const FlowReport &report);
    void refreshTheme();
signals:
    void addressActivated(quint64 address);
protected:
    void wheelEvent(QWheelEvent *event) override;
private:
    QGraphicsScene *scene_;
    FlowReport lastReport_;
};
