#pragma once
#include <QMainWindow>
#include <memory>
#include "BinaryFile.h"
class HexView;
class QLabel;
class QTabWidget;
class QCloseEvent;
class WindowsDebugSession;
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow();
protected:
    void closeEvent(QCloseEvent *event) override;
private:
    void openFile();
    void startDebugSession();
    bool openPath(const QString &path);
    void activateTab(int index);
    void closeTab(int index);
    void saveSession();
    void restoreSession();
    void jumpToOffset();
    void calculateHash();
    void findHex();
    void splitFile();
    void joinFile();
    void analyzeFile();
    void inspectPE();
    void compareFiles();
    void disassembleFile();
    void disassemblePEEntry();
    void displayDisassembly(const struct DisassemblyReport &report,quint64 fileOffset,quint64 address);
    void showAnalysis(const struct AnalysisReport &report);
    std::shared_ptr<BinaryFile> doc_;
    HexView *hex_=nullptr;
    QTabWidget *tabs_=nullptr;
    QLabel *status_=nullptr;
    WindowsDebugSession *debugSession_=nullptr;
};
