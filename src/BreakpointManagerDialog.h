#pragma once
#include <QDialog>
#include <QVector>
#include "BreakpointPreset.h"
class QTableWidget;
class QLabel;
class WindowsDebugSession;
// Preset management is intentionally separate from the live target state.
// A user must explicitly arm a breakpoint and configure an existing one.
class BreakpointManagerDialog final: public QDialog {
    Q_OBJECT
public:
    explicit BreakpointManagerDialog(WindowsDebugSession *session,QWidget *parent=nullptr);
private:
    void addEntry();
    void editEntry();
    void removeEntry();
    void importJson();
    void exportJson();
    void armSelected();
    void configureSelected();
    void updateTable();
    int selectedIndex() const;
    bool editPreset(BreakpointPreset &preset);
    QVector<BreakpointPreset> presets_;
    QTableWidget *table_=nullptr;
    QLabel *status_=nullptr;
    WindowsDebugSession *session_=nullptr;
};
