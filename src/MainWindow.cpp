#include "MainWindow.h"
#include "HexView.h"
#include "SplitEngine.h"
#include "AnalysisEngine.h"
#include "PEInspector.h"
#include "DiffEngine.h"
#include "DisassemblyEngine.h"
#include "ControlFlowEngine.h"
#include "FlowGraphView.h"
#include "CrossReferenceEngine.h"
#include "FunctionAnalysisEngine.h"
#include "CrackmeInsights.h"
#include "WindowsDebugSession.h"
#include "BreakpointManagerDialog.h"
#include <QPlainTextEdit>
#include <QScrollArea>
#include <QJsonObject>
#include <QJsonDocument>
#include <QSaveFile>
#include <QFile>
#include <QDateTime>
#include <QGroupBox>
#include <QTextCursor>
#include <QTextBlock>
#include <QTextDocument>
#include <QTextCharFormat>
#include <QColor>
#include "TaskRunner.h"
#include "AppTheme.h"
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QSpinBox>
#include <QTextEdit>
#include <QtConcurrent/QtConcurrentRun>
#include <QFutureWatcher>
#include <QTimer>
#include <QPointer>
#include <QTabWidget>
#include <QFileInfo>
#include <QSignalBlocker>
#include <QSet>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QMutex>
#include <functional>
#include <QSettings>
#include <QCloseEvent>
#include <atomic>
#include <QDockWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QHeaderView>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QLabel>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QApplication>
#include <QProgressDialog>
#include <QRegularExpression>
#include <algorithm>
#include <limits>
MainWindow::MainWindow() {
    setWindowTitle("YAS BinaryLab X — V4.0");
    resize(1200,760);
    QSettings settings("YAS", "BinaryLabX");
    restoreGeometry(settings.value("window/geometry").toByteArray());
    AppTheme::apply(qApp,settings.value("appearance/dark",true).toBool());
    tabs_=new QTabWidget(this);
    tabs_->setTabsClosable(true);
    tabs_->setMovable(true);
    tabs_->setDocumentMode(true);
    setCentralWidget(tabs_);
    connect(tabs_,&QTabWidget::currentChanged,this,[this](int i){activateTab(i);});
    connect(tabs_,&QTabWidget::tabCloseRequested,this,[this](int i){closeTab(i);});
    auto *fileMenu=menuBar()->addMenu("File");
    auto *tools=menuBar()->addMenu("Tools");
    auto *viewMenu=menuBar()->addMenu("View");
    auto *darkAction=viewMenu->addAction("Gece Teması (Koyu)");
    darkAction->setCheckable(true);
    darkAction->setChecked(settings.value("appearance/dark",true).toBool());
    connect(darkAction,&QAction::toggled,this,[this](bool dark){
        QSettings("YAS","BinaryLabX").setValue("appearance/dark",dark);
        AppTheme::apply(qApp,dark);
        for(auto *graph:findChildren<FlowGraphView*>()) graph->refreshTheme();
        for(auto *view:findChildren<HexView*>()) {
            view->setStyleSheet(QString());
            view->viewport()->update();
        }
    });
    auto *toolbar=addToolBar("Main");
    auto add=[&](QMenu *menu,const QString &title,const QKeySequence &shortcut,auto callback) {
        QAction *a=menu->addAction(title);
        a->setShortcut(shortcut);
        connect(a,&QAction::triggered,this,callback);
        toolbar->addAction(a);
    };
    add(fileMenu,"Open",QKeySequence::Open,[this]{openFile();});
    add(tools,"Copy Selected Hex",QKeySequence::Copy,[this]{if(hex_)hex_->copySelectedHex();});
    add(tools,"Copy Selected ASCII",QKeySequence("Ctrl+Shift+C"),[this]{if(hex_)hex_->copySelectedAscii();});
    add(tools,"Go to Offset",QKeySequence("Ctrl+G"),[this]{jumpToOffset();});
    add(tools,"Find Hex",QKeySequence::Find,[this]{findHex();});
    add(tools,"SHA-256",QKeySequence("Ctrl+H"),[this]{calculateHash();});
    add(tools,"Split File",QKeySequence("Ctrl+Shift+S"),[this]{splitFile();});
    add(tools,"Join Parts",QKeySequence("Ctrl+Shift+J"),[this]{joinFile();});
    add(tools,"Analyze File",QKeySequence("Ctrl+Shift+A"),[this]{analyzeFile();});
    add(tools,"Inspect PE",QKeySequence("Ctrl+Shift+P"),[this]{inspectPE();});
    add(tools,"Compare Files",QKeySequence("Ctrl+Shift+D"),[this]{compareFiles();});
    add(tools,"Launch Windows Debugger",QKeySequence("Ctrl+Shift+F5"),[this]{startDebugSession();});
    add(tools,"Debugger: Toggle Breakpoint",QKeySequence("F2"),[this]{
        if(!debugSession_ || !debugSession_->running())return;
        bool ok=false;
        QString value=QInputDialog::getText(this,"Breakpoint (virtual address)",
            "Hexadecimal VA (e.g. 401000):",QLineEdit::Normal,{},&ok).trimmed();
        if(!ok || value.isEmpty())return;
        if(value.startsWith("0x",Qt::CaseInsensitive))value=value.mid(2);
        const quint64 address=value.toULongLong(&ok,16);
        if(!ok || address==0){QMessageBox::warning(this,"Breakpoint","Invalid virtual address.");return;}
        debugSession_->toggleBreakpoint(address);
    });
    add(tools,"Debugger: Breakpoint Manager",QKeySequence("Ctrl+Shift+B"),[this]{
        BreakpointManagerDialog manager(debugSession_,this);
        manager.exec();
    });
    add(tools,"Debugger: Step Into",QKeySequence("F7"),[this]{if(debugSession_)debugSession_->stepInto();});
    add(tools,"Debugger: Step Over",QKeySequence("F8"),[this]{if(debugSession_)debugSession_->stepOver();});
    add(tools,"Debugger: Continue",QKeySequence("F9"),[this]{if(debugSession_)debugSession_->resume();});
    add(tools,"Disassemble",QKeySequence("Ctrl+Shift+I"),[this]{disassembleFile();});
    add(tools,"Disassemble PE Entry",QKeySequence("Ctrl+Shift+E"),[this]{disassemblePEEntry();});
    status_=new QLabel("Ready",this);
    statusBar()->addWidget(status_,1);
    restoreSession();
}
