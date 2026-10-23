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
void MainWindow::openFile() {
    QString path=QFileDialog::getOpenFileName(this,"Open binary file");
    if(!path.isEmpty()) openPath(path);
}
bool MainWindow::openPath(const QString &path) {
    const QString canonical=QFileInfo(path).canonicalFilePath();
    if(canonical.isEmpty()) return false;
    for(int i=0;i<tabs_->count();++i) {
        auto *view=qobject_cast<HexView*>(tabs_->widget(i));
        if(view && view->property("filePath").toString()==canonical) {
            tabs_->setCurrentIndex(i);
            return true;
        }
    }
    auto candidate=std::make_shared<BinaryFile>();
    if(!candidate->open(canonical)) {
        QMessageBox::warning(this,"Open failed","Cannot read selected file.");
        return false;
    }
    auto *view=new HexView(tabs_);
    view->setProperty("filePath",canonical);
    view->setDocument(candidate);
    const int index=tabs_->addTab(view,QFileInfo(canonical).fileName());
    tabs_->setTabToolTip(index,canonical);
    tabs_->setCurrentIndex(index);
    QSettings("YAS","BinaryLabX").setValue("recent/lastFile",canonical);
    return true;
}
void MainWindow::activateTab(int index) {
    hex_=index>=0 ? qobject_cast<HexView*>(tabs_->widget(index)) : nullptr;
    if(!hex_) {
        doc_.reset();
        status_->setText("Ready — Open a file");
        return;
    }
    const QString path=hex_->property("filePath").toString();
    // Each view owns its own document. Reopen a read-only handle for the active commands.
    auto candidate=std::make_shared<BinaryFile>();
    if(!candidate->open(path)) {
        doc_.reset();
        status_->setText("File is no longer readable: "+path);
        return;
    }
    doc_=std::move(candidate);
    // Show only analysis docks associated with this file.
    for(auto *dock:findChildren<QDockWidget*>()) {
        if(dock->property("analysisPath").isValid())
            dock->setVisible(dock->property("analysisPath").toString()==path);
    }
    status_->setText(QString("%1 | %2 bytes | Read-only").arg(path).arg(doc_->size()));
}
void MainWindow::closeTab(int index) {
    if(index<0 || index>=tabs_->count())return;
    QWidget *page=tabs_->widget(index);
    const QString closingPath=page->property("filePath").toString();
    for(auto *dock:findChildren<QDockWidget*>()) {
        if(dock->property("analysisPath").toString()==closingPath) {
            dock->hide();
            dock->setProperty("analysisPath",QVariant());
        }
    }
    tabs_->removeTab(index);
    page->deleteLater();
    if(tabs_->count()==0) activateTab(-1);
}
void MainWindow::saveSession() {
    QStringList paths;
    QStringList offsets;
    for(int i=0;i<tabs_->count();++i) {
        auto *view=qobject_cast<HexView*>(tabs_->widget(i));
        if(!view)continue;
        paths.append(view->property("filePath").toString());
        offsets.append(QString::number(view->currentOffset()));
    }
    QSettings settings("YAS","BinaryLabX");
    settings.setValue("session/paths",paths);
    settings.setValue("session/offsets",offsets);
    settings.setValue("session/currentIndex",tabs_->currentIndex());
}
void MainWindow::restoreSession() {
    QSettings settings("YAS","BinaryLabX");
    const QStringList paths=settings.value("session/paths").toStringList();
    const QStringList offsets=settings.value("session/offsets").toStringList();
    QSignalBlocker blocker(tabs_);
    for(int i=0;i<paths.size() && i<32;++i) {
        if(!QFileInfo::exists(paths[i]))continue;
        if(!openPath(paths[i]))continue;
        auto *view=qobject_cast<HexView*>(tabs_->currentWidget());
        if(view && i<offsets.size()) {
            bool ok=false;
            const qint64 offset=offsets[i].toLongLong(&ok);
            if(ok && offset>=0)view->jumpTo(offset);
        }
    }
    blocker.unblock();
    if(tabs_->count()>0) {
        const int selected=std::clamp(settings.value("session/currentIndex",0).toInt(),0,tabs_->count()-1);
        tabs_->setCurrentIndex(selected);
        activateTab(selected);
    }
}
void MainWindow::jumpToOffset() {
    if(!doc_) return;
    bool ok=false;
    QString text=QInputDialog::getText(this,"Go to Offset","Hex offset (e.g. 0x1000):",QLineEdit::Normal,"0x0",&ok).trimmed();
    if(!ok || text.isEmpty()) return;
    if(text.startsWith("0x",Qt::CaseInsensitive)) text=text.mid(2);
    qulonglong value=text.toULongLong(&ok,16);
    if(!ok || value>static_cast<qulonglong>(std::numeric_limits<qint64>::max())) {
        QMessageBox::warning(this,"Invalid offset","Enter a valid hexadecimal offset."); return;
    }
    hex_->jumpTo(static_cast<qint64>(value));
}
void MainWindow::calculateHash() {
    if(!doc_) return;
    if(!findChildren<QObject*>("HashWorker").isEmpty()) {
        QMessageBox::information(this,"SHA-256","A hash calculation is already running.");
        return;
    }
    const QString path=doc_->path();
    auto *dialog=new QProgressDialog("Computing SHA-256 in background...","",0,0,this);
    dialog->setCancelButton(nullptr);
    dialog->setWindowModality(Qt::NonModal);
    dialog->setMinimumDuration(0);
    auto *watcher=new QFutureWatcher<QString>(this);
    watcher->setObjectName("HashWorker");
    connect(watcher,&QFutureWatcher<QString>::finished,this,[this,watcher,dialog,path](){
        const QString value=watcher->result();
        dialog->hide();
        dialog->deleteLater();
        watcher->deleteLater();
        if(value.startsWith("ERROR:"))
            QMessageBox::warning(this,"SHA-256",value.mid(6));
        else QMessageBox::information(this,"SHA-256 — "+path,value);
    });
    dialog->show();
    watcher->setFuture(QtConcurrent::run([path](){
        BinaryFile file;
        if(!file.open(path))return QString("ERROR:Cannot open file.");
        QString error;
        QString hash=file.sha256(&error);
        return hash.isEmpty()?QString("ERROR:")+error:hash;
    }));
}
void MainWindow::findHex() {
    if(!doc_) return;
    bool ok=false;
    QString input=QInputDialog::getText(this,"Find Hex","Hex bytes (e.g. 4D 5A):",QLineEdit::Normal,{},&ok);
    if(!ok) return;
    input.remove(QRegularExpression("\\s+"));
    if(input.isEmpty() || input.size()%2 || !QRegularExpression("^[0-9A-Fa-f]+$").match(input).hasMatch()) {
        QMessageBox::warning(this,"Invalid pattern","Enter complete hexadecimal bytes."); return;
    }
    QByteArray pattern=QByteArray::fromHex(input.toLatin1());
    const qint64 chunkSize=1024*1024;
    qint64 offset=std::min(doc_->size(),hex_->currentOffset()+16);
    QByteArray carry;
    QProgressDialog progress("Searching...","Cancel",0,1000,this);
    progress.setWindowModality(Qt::WindowModal);
    while(offset<doc_->size()) {
        if(progress.wasCanceled()) return;
        QByteArray block=doc_->read(offset,chunkSize);
        if(block.isEmpty()) break;
        QByteArray combined=carry+block;
        qsizetype index=combined.indexOf(pattern);
        if(index>=0) {
            qint64 found=offset-carry.size()+index;
            hex_->jumpTo(found);
            status_->setText(QString("Found at 0x%1").arg(static_cast<qulonglong>(found),0,16));
            return;
        }
        carry=combined.right(std::min<qsizetype>(pattern.size()-1,combined.size()));
        offset+=block.size();
        progress.setValue(static_cast<int>(1000.0L*offset/std::max<qint64>(1,doc_->size())));
        QApplication::processEvents();
    }
    QMessageBox::information(this,"Find Hex","Pattern not found after current offset.");
}

void MainWindow::splitFile() {
    QString source=QFileDialog::getOpenFileName(this,"Select file to split");
    if(source.isEmpty()) return;
    QString dest=QFileDialog::getExistingDirectory(this,"Choose output directory");
    if(dest.isEmpty()) return;
    QDialog options(this);
    options.setWindowTitle("Split Options — Compression");
    QFormLayout form(&options);
    auto *sizeBox=new QSpinBox(&options);
    sizeBox->setRange(1,2048);
    sizeBox->setValue(100);
    sizeBox->setSuffix(" MiB");
    auto *compressBox=new QCheckBox("Kayıpsız sıkıştırma (zlib)",&options);
    compressBox->setChecked(true);
    auto *levelBox=new QSpinBox(&options);
    levelBox->setRange(1,9);
    levelBox->setValue(6);
    levelBox->setToolTip("1 = hızlı, 9 = daha yüksek sıkıştırma (daha yavaş)");
    form.addRow("Her parçanın ham veri boyutu",sizeBox);
    form.addRow(compressBox);
    form.addRow("Sıkıştırma seviyesi",levelBox);
    connect(compressBox,&QCheckBox::toggled,levelBox,&QWidget::setEnabled);
    auto *buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel,&options);
    connect(buttons,&QDialogButtonBox::accepted,&options,&QDialog::accept);
    connect(buttons,&QDialogButtonBox::rejected,&options,&QDialog::reject);
    form.addRow(buttons);
    if(options.exec()!=QDialog::Accepted)return;
    const int sizeMb=sizeBox->value();
    const int compression=compressBox->isChecked()?levelBox->value():0;
    struct Outcome { bool success=false; QString error; };
    startBackgroundTask<Outcome>(this,"Splitting file...",
        [source,dest,sizeMb,compression](const auto &progress){
            Outcome result;
            result.success=SplitEngine::split(source,dest,static_cast<qint64>(sizeMb)*1024*1024,progress,result.error,compression);
            return result;
        },[this](Outcome result){
            if(result.success) QMessageBox::information(this,"Split complete","Parts and manifest created. Compressed splits use YAS-SPLIT-2; old YAS-SPLIT-1 is supported.");
            else if(result.error!="Cancelled.") QMessageBox::warning(this,"Split failed",result.error+
                "\nCompleted parts may remain in the output folder.");
            status_->setText(result.success?"Split complete":"Split stopped");
        });
}
void MainWindow::joinFile() {
    QString manifest=QFileDialog::getOpenFileName(this,"Select YAS manifest",{},"YAS Manifest (*.yasmanifest.json);;JSON (*.json)");
    if(manifest.isEmpty()) return;
    QString dest=QFileDialog::getExistingDirectory(this,"Choose output directory");
    if(dest.isEmpty()) return;
    struct Outcome { bool success=false; QString error; };
    startBackgroundTask<Outcome>(this,"Joining and verifying parts...",
        [manifest,dest](const auto &progress){
            Outcome result;
            result.success=SplitEngine::join(manifest,dest,progress,result.error);
            return result;
        },[this](Outcome result){
            if(result.success) QMessageBox::information(this,"Join complete","Reconstructed file verified.");
            else if(result.error!="Cancelled.") QMessageBox::warning(this,"Join failed",result.error);
            status_->setText(result.success?"Join complete":"Join stopped");
        });
}

void MainWindow::analyzeFile() {
    if(!doc_) {
        QMessageBox::information(this,"Analysis","Open a file first.");return;
    }
    if(!findChildren<QObject*>("AnalysisWorker").isEmpty()) {
        QMessageBox::information(this,"Analysis","An analysis is already running.");
        return;
    }
    const QString path=doc_->path();
    auto cancelled=std::make_shared<std::atomic_bool>(false);
    auto processed=std::make_shared<std::atomic<qint64>>(0);
    auto total=std::make_shared<std::atomic<qint64>>(0);
    auto *progress=new QProgressDialog("Analyzing signature, entropy and strings...","Cancel",0,1000,this);
    progress->setAttribute(Qt::WA_DeleteOnClose,false);
    progress->setWindowModality(Qt::NonModal);
    progress->setMinimumDuration(0);
    progress->setAutoClose(false);
    progress->setAutoReset(false);
    connect(progress,&QProgressDialog::canceled,this,[cancelled](){cancelled->store(true);});
    auto *watcher=new QFutureWatcher<AnalysisReport>(this);
    watcher->setObjectName("AnalysisWorker");
    auto *timer=new QTimer(watcher);
    timer->setInterval(80);
    connect(timer,&QTimer::timeout,this,[progress,processed,total](){
        const qint64 t=total->load();
        const qint64 n=processed->load();
        if(t>0) progress->setValue(static_cast<int>(1000.0*n/t));
    });
    connect(watcher,&QFutureWatcher<AnalysisReport>::finished,this,[this,watcher,timer,progress,path](){
        timer->stop();
        AnalysisReport report=watcher->result();
        progress->hide();
        progress->deleteLater();
        watcher->deleteLater();
        if(!report.error.isEmpty()) {
            if(!report.cancelled) QMessageBox::warning(this,"Analysis failed",report.error);
            return;
        }
        if(!doc_ || doc_->path()!=path || !hex_ || hex_->property("filePath").toString()!=path) {
            status_->setText("Analysis finished for a file no longer open.");
            return;
        }
        showAnalysis(report);
    });
    progress->show();
    timer->start();
    watcher->setFuture(QtConcurrent::run([path,cancelled,processed,total](){
        return AnalysisEngine::analyze(path,[cancelled,processed,total](qint64 n,qint64 t){
            processed->store(n);
            total->store(t);
            return !cancelled->load();
        });
    }));
}
void MainWindow::showAnalysis(const AnalysisReport &report) {
    // Rebuild dedicated docks so repeated analyses never duplicate widgets.
    for(const QString &name : {QString("FileIntelligenceDock"),QString("EntropyDock"),QString("StringsDock")}) {
        if(auto *dock=findChild<QDockWidget*>(name)) {
            removeDockWidget(dock);
            delete dock;
        }
    }
    auto *structureDock=new QDockWidget("File Intelligence",this);
    structureDock->setObjectName("FileIntelligenceDock");
    auto *tree=new QTreeWidget(structureDock);
    tree->setHeaderLabels({"Property","Value"});
    auto add=[&](const QString &key,const QString &value){
        auto *item=new QTreeWidgetItem(tree);
        item->setText(0,key);item->setText(1,value);
    };
    add("Detected type",report.fileType);
    add("Magic bytes",report.signature.isEmpty()?"No known signature":report.signature);
    add("File size",QString::number(report.fileSize)+" bytes");
    add("Entropy windows",QString::number(report.entropy.size()));
    add("Extracted strings",QString::number(report.strings.size()));
    tree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    structureDock->setWidget(tree);
    addDockWidget(Qt::LeftDockWidgetArea,structureDock);
    auto *entropyDock=new QDockWidget("Entropy Map (256 KiB windows)",this);
    entropyDock->setObjectName("EntropyDock");
    auto *entropyTable=new QTableWidget(entropyDock);
    entropyTable->setColumnCount(3);
    entropyTable->setHorizontalHeaderLabels({"Offset (hex)","Bytes","Bits / byte"});
    const int entropyRows=std::min<int>(report.entropy.size(),20000);
    entropyTable->setRowCount(entropyRows);
    for(int i=0;i<entropyRows;++i) {
        const auto &e=report.entropy[i];
        entropyTable->setItem(i,0,new QTableWidgetItem(QString::number(e.offset,16).toUpper()));
        entropyTable->setItem(i,1,new QTableWidgetItem(QString::number(e.size)));
        entropyTable->setItem(i,2,new QTableWidgetItem(QString::number(e.bitsPerByte,'f',3)));
    }
    entropyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    entropyTable->horizontalHeader()->setStretchLastSection(true);
    connect(entropyTable,&QTableWidget::cellDoubleClicked,this,[this,report](int row,int){
        if(row>=0 && row<report.entropy.size()) hex_->jumpTo(report.entropy[row].offset);
    });
    entropyDock->setWidget(entropyTable);
    addDockWidget(Qt::RightDockWidgetArea,entropyDock);
    auto *stringsDock=new QDockWidget("Extracted Strings",this);
    stringsDock->setObjectName("StringsDock");
    auto *stringsTable=new QTableWidget(stringsDock);
    stringsTable->setColumnCount(3);
    stringsTable->setHorizontalHeaderLabels({"Offset (hex)","Encoding","String"});
    stringsTable->setRowCount(static_cast<int>(report.strings.size()));
    for(int i=0;i<report.strings.size();++i) {
        const auto &item=report.strings[i];
        stringsTable->setItem(i,0,new QTableWidgetItem(QString::number(item.offset,16).toUpper()));
        stringsTable->setItem(i,1,new QTableWidgetItem(item.encoding));
        stringsTable->setItem(i,2,new QTableWidgetItem(item.value));
    }
    stringsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    stringsTable->horizontalHeader()->setStretchLastSection(true);
    connect(stringsTable,&QTableWidget::cellDoubleClicked,this,[this,report](int row,int){
        if(row>=0 && row<report.strings.size()) hex_->jumpTo(report.strings[row].offset);
    });
    stringsDock->setWidget(stringsTable);
    addDockWidget(Qt::BottomDockWidgetArea,stringsDock);
    resizeDocks({structureDock,entropyDock},{280,350},Qt::Horizontal);
    resizeDocks({stringsDock},{220},Qt::Vertical);
    status_->setText("Analysis completed: "+report.fileType);
}

void MainWindow::inspectPE() {
    if(!doc_) {QMessageBox::information(this,"PE Inspector","Open a file first.");return;}
    PEReport report=PEInspector::inspect(doc_->path());
    if(!report.valid) {QMessageBox::warning(this,"PE Inspector",report.error);return;}
    auto *dock=findChild<QDockWidget*>("PEDock");
    if(!dock) {
        dock=new QDockWidget("PE Structure",this);
        dock->setObjectName("PEDock");
        addDockWidget(Qt::RightDockWidgetArea,dock);
    }
    auto *table=new QTreeWidget(dock);
    table->setHeaderLabels({"PE field","Value"});
    auto item=[&](const QString &k,const QString &v) {
        auto *row=new QTreeWidgetItem(table);
        row->setText(0,k);row->setText(1,v);
    };
    item("Architecture",report.architecture);
    item("Sections",QString::number(report.sectionCount));
    item("Image base",QString("0x%1").arg(report.imageBase,0,16));
    item("Entry RVA",QString("0x%1").arg(report.entryPointRva,0,16));
    item("Imported DLLs",QString::number(report.imports.size()));
    if(!report.importWarning.isEmpty()) item("Import warning",report.importWarning);
    for(const auto &imp:report.imports) {
        auto *dll=new QTreeWidgetItem(table);
        dll->setText(0,imp.dll);
        dll->setText(1,QString("%1 symbols").arg(imp.functions.size()));
        for(const auto &symbol:imp.functions) {
            auto *fn=new QTreeWidgetItem(dll);
            fn->setText(0,symbol);
        }
    }
    for(const auto &section:report.sections) {
        item(section.name,QString("RVA 0x%1 | Raw 0x%2 | %3 bytes")
            .arg(section.virtualAddress,0,16).arg(section.rawOffset,0,16).arg(section.rawSize));
    }
    table->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    dock->setWidget(table);
    dock->setProperty("analysisPath",doc_?doc_->path():QString());
    dock->show();
}
void MainWindow::compareFiles() {
    QString left=QFileDialog::getOpenFileName(this,"Select first file");
    if(left.isEmpty()) return;
    QString right=QFileDialog::getOpenFileName(this,"Select second file");
    if(right.isEmpty()) return;
    startBackgroundTask<DiffReport>(this,"Comparing binary files...",
        [left,right](const auto &progress){
            return DiffEngine::compare(left,right,progress);
        },[this](DiffReport report){
            if(!report.error.isEmpty()) {
                if(!report.cancelled) QMessageBox::warning(this,"Diff error",report.error);
                return;
            }
    auto *dock=findChild<QDockWidget*>("DiffDock");
    if(!dock) {
        dock=new QDockWidget("Binary Diff",this);
        dock->setObjectName("DiffDock");
        addDockWidget(Qt::BottomDockWidgetArea,dock);
    }
    auto *table=new QTableWidget(dock);
    table->setColumnCount(2);
    table->setHorizontalHeaderLabels({"Changed offset (hex)","Length (bytes)"});
    table->setRowCount(report.ranges.size());
    for(int i=0;i<report.ranges.size();++i) {
        table->setItem(i,0,new QTableWidgetItem(QString::number(report.ranges[i].offset,16).toUpper()));
        table->setItem(i,1,new QTableWidgetItem(QString::number(report.ranges[i].length)));
    }
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setStretchLastSection(true);
    dock->setWidget(table);
    dock->setProperty("analysisPath",doc_?doc_->path():QString());
    dock->show();
    status_->setText(QString("Diff: %1 changed bytes, %2 ranges%3")
        .arg(report.changedBytes).arg(report.ranges.size()).arg(report.truncated?" (range list capped)":""));
    });
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if(property("yas.activeTasks").toInt()>0 || !findChildren<QObject*>("HashWorker").isEmpty()) {
        QMessageBox::information(this,"Background tasks running",
            "Wait for active tasks to finish or cancel them before closing. "
            "This prevents worker callbacks from accessing destroyed UI objects.");
        event->ignore();
        return;
    }
    if(debugSession_)debugSession_->stop();
    QSettings settings("YAS","BinaryLabX");
    settings.setValue("window/geometry",saveGeometry());
    settings.setValue("window/dockState",saveState());
    saveSession();
    QMainWindow::closeEvent(event);
}

