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
void MainWindow::disassembleFile() {
    if(!doc_) {QMessageBox::information(this,"Disassembly","Open a binary file first.");return;}
    QDialog dialog(this);
    dialog.setWindowTitle("Disassembly settings");
    QFormLayout layout(&dialog);
    QLineEdit offsetInput(QString("0x%1").arg(hex_->currentOffset(),0,16),&dialog);
    QLineEdit addressInput(QString("0x%1").arg(hex_->currentOffset(),0,16),&dialog);
    QComboBox architecture(&dialog);
    architecture.addItems({"x86-64","x86 (32-bit)"});
    QSpinBox count(&dialog);
    count.setRange(1,2000);count.setValue(300);
    layout.addRow("File offset (hex)",&offsetInput);
    layout.addRow("Virtual address (hex)",&addressInput);
    layout.addRow("Architecture",&architecture);
    layout.addRow("Maximum instructions",&count);
    QDialogButtonBox buttons(QDialogButtonBox::Ok|QDialogButtonBox::Cancel,&dialog);
    layout.addRow(&buttons);
    connect(&buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);
    connect(&buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
    if(dialog.exec()!=QDialog::Accepted)return;
    auto parseHex=[](QString text,bool &ok)->quint64 {
        text=text.trimmed();if(text.startsWith("0x",Qt::CaseInsensitive))text=text.mid(2);
        return text.toULongLong(&ok,16);
    };
    bool okOffset=false,okAddress=false;
    quint64 offset=parseHex(offsetInput.text(),okOffset);
    quint64 address=parseHex(addressInput.text(),okAddress);
    if(!okOffset||!okAddress||offset>=static_cast<quint64>(doc_->size())) {
        QMessageBox::warning(this,"Invalid offset","Enter valid hexadecimal offsets.");return;
    }
    DisassemblyReport report=DisassemblyEngine::decode(doc_->path(),offset,address,
        architecture.currentIndex()==0,count.value());
    if(!report.error.isEmpty()) {
        QMessageBox::warning(this,"Disassembly",report.error);return;
    }
    displayDisassembly(report,offset,address);
}
void MainWindow::disassemblePEEntry() {
    if(!doc_) {QMessageBox::information(this,"PE Entry","Open an EXE or DLL first.");return;}
    const PEReport pe=PEInspector::inspect(doc_->path());
    if(!pe.valid) {QMessageBox::warning(this,"PE Entry",pe.error);return;}
    if(pe.architecture!="x86" && pe.architecture!="x86-64") {
        QMessageBox::warning(this,"Unsupported architecture","Entry point disassembly currently supports x86 and x86-64 only.");return;
    }
    quint64 fileOffset=0;
    if(!PEInspector::rvaToFileOffset(pe,pe.entryPointRva,static_cast<quint64>(doc_->size()),fileOffset)) {
        QMessageBox::warning(this,"PE Entry","Entry RVA does not map to file-backed section bytes.");return;
    }
    if(pe.imageBase>UINT64_MAX-static_cast<quint64>(pe.entryPointRva)) {
        QMessageBox::warning(this,"PE Entry","Virtual address overflow.");return;
    }
    const quint64 address=pe.imageBase+pe.entryPointRva;
    DisassemblyReport report=DisassemblyEngine::decode(doc_->path(),fileOffset,address,
                                                       pe.architecture=="x86-64",300);
    if(!report.error.isEmpty()) {QMessageBox::warning(this,"PE Entry",report.error);return;}
    displayDisassembly(report,fileOffset,address);
}
void MainWindow::displayDisassembly(const DisassemblyReport &report,quint64 offset,quint64 address) {
    auto *dock=findChild<QDockWidget*>("DisassemblyDock");
    if(!dock) {
        dock=new QDockWidget("Disassembly",this);
        dock->setObjectName("DisassemblyDock");
        addDockWidget(Qt::BottomDockWidgetArea,dock);
    }
    auto *table=new QTableWidget(dock);
    table->setColumnCount(4);
    table->setHorizontalHeaderLabels({"Address","Bytes","Instruction","Operands"});
    table->setRowCount(report.instructions.size());
    for(int i=0;i<report.instructions.size();++i) {
        const Instruction &ins=report.instructions[i];
        table->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(ins.address,0,16)));
        table->setItem(i,1,new QTableWidgetItem(ins.bytes));
        table->setItem(i,2,new QTableWidgetItem(ins.mnemonic));
        table->setItem(i,3,new QTableWidgetItem(ins.operands));
    }
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setStretchLastSection(true);
    connect(table,&QTableWidget::cellDoubleClicked,this,[this,report,offset,address,sourcePath=doc_?doc_->path():QString()](int row,int){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath)return;
        if(row<0||row>=report.instructions.size())return;
        quint64 va=report.instructions[row].address;
        if(va<address)return;
        quint64 delta=va-address;
        if(delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    dock->setWidget(table);
    dock->setProperty("analysisPath",doc_?doc_->path():QString());
    dock->show();
    // Static crackme learning assistant: compare/branch and direct-call clues only.
    const QVector<CrackmeInsight> clues=CrackmeInsights::scan(report);
    auto *clueDock=findChild<QDockWidget*>("CrackmeInsightsDock");
    if(!clueDock) {
        clueDock=new QDockWidget("Crackme Lab — Static Clues",this);
        clueDock->setObjectName("CrackmeInsightsDock");
        addDockWidget(Qt::RightDockWidgetArea,clueDock);
    }
    auto *clueTable=new QTableWidget(clueDock);
    clueTable->setColumnCount(4);
    clueTable->setHorizontalHeaderLabels({"Address","Pattern","Details","Interpretation limit"});
    clueTable->setRowCount(clues.size());
    for(int i=0;i<clues.size();++i) {
        const auto &clue=clues[i];
        clueTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(clue.address,0,16)));
        clueTable->setItem(i,1,new QTableWidgetItem(clue.category));
        clueTable->setItem(i,2,new QTableWidgetItem(clue.detail));
        clueTable->setItem(i,3,new QTableWidgetItem(clue.caution));
    }
    clueTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    clueTable->horizontalHeader()->setStretchLastSection(true);
    const QString clueSourcePath=doc_?doc_->path():QString();
    connect(clueTable,&QTableWidget::cellDoubleClicked,this,
            [this,clues,clueSourcePath,offset,address](int row,int){
        if(!hex_ || hex_->property("filePath").toString()!=clueSourcePath)return;
        if(row<0 || row>=clues.size())return;
        const quint64 va=clues[row].address;
        if(va<address)return;
        const quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    clueDock->setWidget(clueTable);
    clueDock->setProperty("analysisPath",clueSourcePath);
    clueDock->show();
    // Direct control-flow references only: does not infer functions or indirect targets.
    auto *branches=findChild<QDockWidget*>("BranchReferencesDock");
    if(!branches) {
        branches=new QDockWidget("Direct Branch References",this);
        branches->setObjectName("BranchReferencesDock");
        addDockWidget(Qt::RightDockWidgetArea,branches);
    }
    auto *refs=new QTableWidget(branches);
    refs->setColumnCount(3);
    refs->setHorizontalHeaderLabels({"From","Branch","Target"});
    QVector<int> branchRows;
    for(int i=0;i<report.instructions.size();++i) {
        const auto &ins=report.instructions[i];
        const QString op=ins.mnemonic.toLower();
        if(op=="call" || op=="jmp" || op.startsWith('j') || op=="loop" || op=="loope" || op=="loopne")
            branchRows.append(i);
    }
    refs->setRowCount(branchRows.size());
    for(int i=0;i<branchRows.size();++i) {
        const auto &ins=report.instructions[branchRows[i]];
        refs->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(ins.address,0,16)));
        refs->setItem(i,1,new QTableWidgetItem(ins.mnemonic));
        refs->setItem(i,2,new QTableWidgetItem(ins.operands));
    }
    refs->setEditTriggers(QAbstractItemView::NoEditTriggers);
    refs->horizontalHeader()->setStretchLastSection(true);
    branches->setWidget(refs);
    branches->setProperty("analysisPath",doc_?doc_->path():QString());
    branches->show();
    // Control flow from the decoded instruction window; not full program recovery.
    const FlowReport flowReport=ControlFlowEngine::build(report);
    auto *flowDock=findChild<QDockWidget*>("ControlFlowDock");
    if(!flowDock) {
        flowDock=new QDockWidget("Control Flow — Basic Blocks",this);
        flowDock->setObjectName("ControlFlowDock");
        addDockWidget(Qt::RightDockWidgetArea,flowDock);
    }
    auto *flowTree=new QTreeWidget(flowDock);
    flowTree->setHeaderLabels({"Block / edge","Target","Classification"});
    for(const auto &block:flowReport.blocks) {
        auto *parent=new QTreeWidgetItem(flowTree);
        parent->setText(0,QString("Block %1").arg(block.firstInstruction));
        parent->setText(1,QString("0x%1").arg(block.start,0,16));
        parent->setText(2,QString("%1 instructions").arg(block.lastInstruction-block.firstInstruction+1));
        parent->setData(0,Qt::UserRole,QVariant::fromValue(static_cast<qulonglong>(block.start)));
        for(const auto &edge:flowReport.edges) {
            if(edge.from!=block.start)continue;
            auto *child=new QTreeWidgetItem(parent);
            child->setText(0,edge.kind);
            child->setText(1,edge.kind.startsWith("indirect")?"Unresolved":
                           QString("0x%1").arg(edge.to,0,16));
            child->setText(2,edge.targetDecoded?"Decoded":"External / unknown");
            if(edge.targetDecoded)
                child->setData(0,Qt::UserRole,QVariant::fromValue(static_cast<qulonglong>(edge.to)));
        }
    }
    connect(flowTree,&QTreeWidget::itemDoubleClicked,this,[this,offset,address,sourcePath=doc_?doc_->path():QString()](QTreeWidgetItem *item,int){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath)return;
        if(!item->data(0,Qt::UserRole).isValid())return;
        quint64 va=item->data(0,Qt::UserRole).toULongLong();
        if(va<address)return;
        quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    flowTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    flowDock->setWidget(flowTree);
    flowDock->setProperty("analysisPath",doc_?doc_->path():QString());
    flowDock->show();
    auto *graphDock=findChild<QDockWidget*>("FlowGraphDock");
    if(!graphDock) {
        graphDock=new QDockWidget("Visual Control Flow Graph",this);
        graphDock->setObjectName("FlowGraphDock");
        addDockWidget(Qt::RightDockWidgetArea,graphDock);
    }
    auto *graphView=new FlowGraphView(graphDock);
    graphView->setReport(flowReport);
    const QString sourcePath=doc_?doc_->path():QString();
    connect(graphView,&FlowGraphView::addressActivated,this,[this,sourcePath,offset,address](quint64 va){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath || va<address)return;
        const quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    graphDock->setWidget(graphView);
    graphDock->setProperty("analysisPath",sourcePath);
    graphDock->show();
    const CrossReferenceReport crossRefs=CrossReferenceEngine::analyze(report);
    auto *xrefDock=findChild<QDockWidget*>("CrossReferenceDock");
    if(!xrefDock) {
        xrefDock=new QDockWidget("Direct Cross References",this);
        xrefDock->setObjectName("CrossReferenceDock");
        addDockWidget(Qt::RightDockWidgetArea,xrefDock);
    }
    auto *xrefTable=new QTableWidget(xrefDock);
    xrefTable->setColumnCount(4);
    xrefTable->setHorizontalHeaderLabels({"Source","Target","Instruction","Scope"});
    xrefTable->setRowCount(crossRefs.references.size());
    for(int i=0;i<crossRefs.references.size();++i) {
        const auto &ref=crossRefs.references[i];
        xrefTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(ref.from,0,16)));
        xrefTable->setItem(i,1,new QTableWidgetItem(QString("0x%1").arg(ref.to,0,16)));
        xrefTable->setItem(i,2,new QTableWidgetItem(ref.mnemonic));
        xrefTable->setItem(i,3,new QTableWidgetItem(ref.targetInWindow?"Decoded":"Outside window"));
    }
    xrefTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    xrefTable->horizontalHeader()->setStretchLastSection(true);
    connect(xrefTable,&QTableWidget::cellDoubleClicked,this,
            [this,crossRefs,sourcePath,offset,address](int row,int column){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
           row<0 || row>=crossRefs.references.size())return;
        const auto &ref=crossRefs.references[row];
        const quint64 va=column==0?ref.from:ref.to;
        if(va<address || (column!=0 && !ref.targetInWindow))return;
        const quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    xrefDock->setWidget(xrefTable);
    xrefDock->setProperty("analysisPath",sourcePath);
    xrefDock->show();
    auto *functionDock=findChild<QDockWidget*>("FunctionCandidatesDock");
    if(!functionDock) {
        functionDock=new QDockWidget("Function Candidates — Direct Calls",this);
        functionDock->setObjectName("FunctionCandidatesDock");
        addDockWidget(Qt::RightDockWidgetArea,functionDock);
    }
    auto *functionTable=new QTableWidget(functionDock);
    functionTable->setColumnCount(3);
    functionTable->setHorizontalHeaderLabels({"Candidate entry","Direct callers","Scope"});
    functionTable->setRowCount(crossRefs.functions.size());
    for(int i=0;i<crossRefs.functions.size();++i) {
        const auto &f=crossRefs.functions[i];
        functionTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(f.entry,0,16)));
        functionTable->setItem(i,1,new QTableWidgetItem(QString::number(f.callCount)));
        functionTable->setItem(i,2,new QTableWidgetItem(f.inWindow?"Decoded":"Outside window"));
    }
    functionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    functionTable->horizontalHeader()->setStretchLastSection(true);
    connect(functionTable,&QTableWidget::cellDoubleClicked,this,
            [this,crossRefs,sourcePath,offset,address](int row,int){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
           row<0 || row>=crossRefs.functions.size())return;
        const auto &f=crossRefs.functions[row];
        if(!f.inWindow || f.entry<address)return;
        const quint64 delta=f.entry-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    functionDock->setWidget(functionTable);
    functionDock->setProperty("analysisPath",sourcePath);
    functionDock->show();
    const FunctionAnalysisReport functionAnalysis=FunctionAnalysisEngine::analyze(report);
    auto *regionDock=findChild<QDockWidget*>("FunctionRegionsDock");
    if(!regionDock) {
        regionDock=new QDockWidget("Function Regions (Heuristic)",this);
        regionDock->setObjectName("FunctionRegionsDock");
        addDockWidget(Qt::RightDockWidgetArea,regionDock);
    }
    auto *regionTable=new QTableWidget(regionDock);
    regionTable->setColumnCount(5);
    regionTable->setHorizontalHeaderLabels({"Entry","Last decoded","Instructions","Callers","End / Scope"});
    regionTable->setRowCount(functionAnalysis.regions.size());
    for(int i=0;i<functionAnalysis.regions.size();++i) {
        const auto &f=functionAnalysis.regions[i];
        regionTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(f.entry,0,16)));
        regionTable->setItem(i,1,new QTableWidgetItem(f.entryInWindow?QString("0x%1").arg(f.lastAddress,0,16):"—"));
        regionTable->setItem(i,2,new QTableWidgetItem(QString::number(f.instructionCount)));
        regionTable->setItem(i,3,new QTableWidgetItem(QString::number(f.directCallers)));
        regionTable->setItem(i,4,new QTableWidgetItem(!f.entryInWindow?"External":f.terminatesWithReturn?"RET":"Uncertain"));
    }
    regionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    regionTable->horizontalHeader()->setStretchLastSection(true);
    connect(regionTable,&QTableWidget::cellDoubleClicked,this,
            [this,functionAnalysis,sourcePath,offset,address](int row,int){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
           row<0 || row>=functionAnalysis.regions.size())return;
        const auto &region=functionAnalysis.regions[row];
        if(!region.entryInWindow || region.entry<address)return;
        const quint64 delta=region.entry-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    regionDock->setWidget(regionTable);
    regionDock->setProperty("analysisPath",sourcePath);
    regionDock->show();
    auto *callDock=findChild<QDockWidget*>("CallGraphDock");
    if(!callDock) {
        callDock=new QDockWidget("Direct Call Graph — Edges",this);
        callDock->setObjectName("CallGraphDock");
        addDockWidget(Qt::RightDockWidgetArea,callDock);
    }
    auto *callTable=new QTableWidget(callDock);
    callTable->setColumnCount(4);
    callTable->setHorizontalHeaderLabels({"Caller region","Call site","Target","Scope"});
    callTable->setRowCount(functionAnalysis.calls.size());
    for(int i=0;i<functionAnalysis.calls.size();++i) {
        const auto &edge=functionAnalysis.calls[i];
        callTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(edge.callerRegion,0,16)));
        callTable->setItem(i,1,new QTableWidgetItem(QString("0x%1").arg(edge.instructionAddress,0,16)));
        callTable->setItem(i,2,new QTableWidgetItem(QString("0x%1").arg(edge.target,0,16)));
        callTable->setItem(i,3,new QTableWidgetItem(edge.targetInWindow?"Decoded":"External"));
    }
    callTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    callTable->horizontalHeader()->setStretchLastSection(true);
    connect(callTable,&QTableWidget::cellDoubleClicked,this,
            [this,functionAnalysis,sourcePath,offset,address](int row,int column){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
           row<0 || row>=functionAnalysis.calls.size())return;
        const auto &edge=functionAnalysis.calls[row];
        if(column==2 && !edge.targetInWindow)return;
        const quint64 va=column==0?edge.callerRegion:column==2?edge.target:edge.instructionAddress;
        if(va<address)return;
        const quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    callDock->setWidget(callTable);
    callDock->setProperty("analysisPath",sourcePath);
    callDock->show();
    // Visual call graph: nodes are heuristic function regions, not proven functions.
    FlowReport callGraph;
    QSet<quint64> functionAddresses;
    for(const auto &region:functionAnalysis.regions) {
        if(functionAddresses.contains(region.entry))continue;
        functionAddresses.insert(region.entry);
        FlowBlock block;
        block.start=region.entry;
        block.endExclusive=region.lastAddress;
        block.firstInstruction=0;
        block.lastInstruction=std::max(0,region.instructionCount-1);
        callGraph.blocks.append(block);
    }
    for(const auto &call:functionAnalysis.calls) {
        if(!functionAddresses.contains(call.callerRegion))continue;
        callGraph.edges.append({call.callerRegion,call.target,"call",
            functionAddresses.contains(call.target)});
    }
    auto *visualCallDock=findChild<QDockWidget*>("VisualCallGraphDock");
    if(!visualCallDock) {
        visualCallDock=new QDockWidget("Visual Function Call Graph",this);
        visualCallDock->setObjectName("VisualCallGraphDock");
        addDockWidget(Qt::RightDockWidgetArea,visualCallDock);
    }
    auto *visualCallView=new FlowGraphView(visualCallDock);
    visualCallView->setReport(callGraph);
    connect(visualCallView,&FlowGraphView::addressActivated,this,
        [this,sourcePath,offset,address,functionAddresses](quint64 va){
            if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
               !functionAddresses.contains(va) || va<address)return;
            const quint64 delta=va-address;
            if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
               delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
            hex_->jumpTo(static_cast<qint64>(offset+delta));
        });
    visualCallDock->setWidget(visualCallView);
    visualCallDock->setProperty("analysisPath",sourcePath);
    visualCallDock->show();
    status_->setText(QString("Disassembled %1 instructions; %2 branch instructions")
        .arg(report.instructions.size()).arg(branchRows.size()));
}

