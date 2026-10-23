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
void MainWindow::startDebugSession() {
#ifndef Q_OS_WIN
    QMessageBox::warning(this,"Debugger","This debugger requires Windows x64.");
    return;
#else
    if(debugSession_ && debugSession_->running()) {
        QMessageBox::information(this,"Debugger","A debug session is already running.");return;
    }
    const QString path=QFileDialog::getOpenFileName(this,"Select a trusted Windows program",{},"Windows executables (*.exe)");
    if(path.isEmpty())return;
    if(QMessageBox::warning(this,"Execute program under debugger",
       "This operation EXECUTES the selected program on your computer. Only debug software you trust, preferably inside a disposable VM. Continue?",
       QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    if(!debugSession_)debugSession_=new WindowsDebugSession(this);
    auto *dock=findChild<QDockWidget*>("WindowsDebuggerDock");
    if(!dock) {
        dock=new QDockWidget("Windows Debugger — Events / Registers",this);
        dock->setObjectName("WindowsDebuggerDock");
        auto *panel=new QWidget(dock);
        auto *layout=new QVBoxLayout(panel);
        auto *state=new QLabel("Idle",panel);
        state->setObjectName("DebuggerState");
        auto *registers=new QPlainTextEdit(panel);
        registers->setObjectName("DebuggerRegisters");
        registers->setReadOnly(true);
        registers->setPlaceholderText("Registers captured at a debug exception");
        registers->setMaximumHeight(170);
        auto *stack=new QPlainTextEdit(panel);
        stack->setObjectName("DebuggerStack");
        stack->setReadOnly(true);
        stack->setPlaceholderText("Stack snapshot (RSP)");
        stack->setMaximumHeight(170);
        auto *log=new QPlainTextEdit(panel);
        log->setObjectName("DebuggerLog");
        log->setReadOnly(true);
        auto *continueButton=new QPushButton("Continue (F9)",panel);
        auto *stepIntoButton=new QPushButton("Step Into (F7)",panel);
        auto *stepOverButton=new QPushButton("Step Over (F8)",panel);
        auto *toggleBreakpointButton=new QPushButton("Toggle breakpoint (F2)",panel);
        auto *detachButton=new QPushButton("Detach",panel);
        layout->addWidget(state);
        layout->addWidget(registers);
        layout->addWidget(stack);
        auto *disassembly=new QPlainTextEdit(panel);
        disassembly->setObjectName("DebuggerLiveDisassembly");
        disassembly->setReadOnly(true);
        disassembly->setPlaceholderText("Live instructions at RIP (Capstone optional)");
        disassembly->setMaximumHeight(260);
        auto *breakpoints=new QPlainTextEdit(panel);
        breakpoints->setObjectName("DebuggerBreakpointList");
        breakpoints->setReadOnly(true);
        breakpoints->setMaximumHeight(110);
        layout->addWidget(new QLabel("Live Disassembly — RIP",panel));
        layout->addWidget(disassembly);
        layout->addWidget(new QLabel("Software breakpoints",panel));
        layout->addWidget(breakpoints);
        auto *flags=new QPlainTextEdit(panel);
        flags->setObjectName("DebuggerCpuFlags");
        flags->setReadOnly(true);
        flags->setMaximumHeight(75);
        auto *dump=new QPlainTextEdit(panel);
        dump->setObjectName("DebuggerMemoryDump");
        dump->setReadOnly(true);
        dump->setMaximumHeight(190);
        auto *map=new QPlainTextEdit(panel);
        map->setObjectName("DebuggerMemoryMap");
        map->setReadOnly(true);
        map->setMaximumHeight(190);
        layout->addWidget(new QLabel("CPU Flags (EFLAGS)",panel));
        layout->addWidget(flags);
        auto *memoryAddress=new QLineEdit(panel);
        memoryAddress->setObjectName("DebuggerMemoryAddress");
        memoryAddress->setPlaceholderText("Virtual address (hex), e.g. 7FF612340000");
        memoryAddress->setToolTip("Read-only dump of 256 bytes. Available only while paused.");
        auto *memoryReadButton=new QPushButton("Read Memory (Hex)",panel);
        connect(memoryReadButton,&QPushButton::clicked,this,[this,memoryAddress]{
            if(!debugSession_ || !debugSession_->running())return;
            QString input=memoryAddress->text().trimmed();
            if(input.startsWith("0x",Qt::CaseInsensitive))input=input.mid(2);
            bool ok=false;
            const quint64 address=input.toULongLong(&ok,16);
            if(!ok || address==0){
                QMessageBox::warning(this,"Memory address","Enter a valid nonzero hexadecimal virtual address.");
                return;
            }
            debugSession_->requestMemory(address);
        });
        auto *memoryToolbar=new QHBoxLayout;
        memoryToolbar->addWidget(memoryAddress);
        memoryToolbar->addWidget(memoryReadButton);
        layout->addLayout(memoryToolbar);
        layout->addWidget(new QLabel("Live Memory Dump — RIP (read-only)",panel));
        layout->addWidget(dump);
        layout->addWidget(new QLabel("Memory Map (first 256 committed regions)",panel));
        layout->addWidget(map);
        auto *threads=new QPlainTextEdit(panel);
        threads->setObjectName("DebuggerThreadExplorer");
        threads->setReadOnly(true);
        threads->setMaximumHeight(160);
        auto *modules=new QPlainTextEdit(panel);
        modules->setObjectName("DebuggerModuleExplorer");
        modules->setReadOnly(true);
        modules->setMaximumHeight(180);
        auto *history=new QPlainTextEdit(panel);
        history->setObjectName("DebuggerRegisterHistory");
        history->setReadOnly(true);
        history->setMaximumHeight(175);
        auto *threadPicker=new QLineEdit(panel);
        threadPicker->setPlaceholderText("Thread ID in hex, e.g. 00001234");
        auto *inspectThreadButton=new QPushButton("Inspect thread snapshot",panel);
        connect(inspectThreadButton,&QPushButton::clicked,this,[this,threadPicker]{
            if(!debugSession_ || !debugSession_->running())return;
            QString value=threadPicker->text().trimmed();
            if(value.startsWith("0x",Qt::CaseInsensitive))value=value.mid(2);
            bool ok=false;quint32 id=value.toUInt(&ok,16);
            if(!ok || !id){QMessageBox::warning(this,"Thread","Enter a valid hexadecimal thread ID.");return;}
            debugSession_->inspectThread(id);
        });
        layout->addWidget(threadPicker);
        layout->addWidget(inspectThreadButton);
        auto *callstack=new QPlainTextEdit(panel);
        callstack->setObjectName("DebuggerCallStackCandidates");
        callstack->setReadOnly(true);
        callstack->setMaximumHeight(190);
        auto *unwound=new QPlainTextEdit(panel);
        unwound->setObjectName("DebuggerUnwoundCallStack");
        unwound->setReadOnly(true);
        unwound->setMaximumHeight(225);
        layout->addWidget(new QLabel("Unwound call stack — DbgHelp / local symbols",panel));
        layout->addWidget(unwound);
        auto *navigateCallStack=new QPushButton("Inspect selected frame address in Memory Dump",panel);
        navigateCallStack->setToolTip("Select a DbgHelp call stack line and inspect the corresponding virtual address. Does not alter execution.");
        connect(navigateCallStack,&QPushButton::clicked,this,[this,unwound,memoryAddress]{
            if(!debugSession_ || !debugSession_->running())return;
            const QString line=unwound->textCursor().block().text();
            const QRegularExpression expression(QStringLiteral("0x([0-9a-fA-F]{1,16})\\b"));
            const auto match=expression.match(line);
            if(!match.hasMatch()){
                QMessageBox::information(this,"Call Stack","Select a stack frame line containing a virtual address.");
                return;
            }
            bool ok=false;
            const quint64 va=match.captured(1).toULongLong(&ok,16);
            if(!ok || !va)return;
            memoryAddress->setText(QString::number(va,16).toUpper());
            debugSession_->requestMemory(va);
        });
        layout->addWidget(navigateCallStack);
        layout->addWidget(new QLabel("Possible return addresses (not a full unwind)",panel));
        layout->addWidget(callstack);
        auto *memoryPattern=new QLineEdit(panel);
        memoryPattern->setPlaceholderText("HEX bytes to search, e.g. 4D 5A");
        auto *searchButton=new QPushButton("Search Memory — max 1 MiB",panel);
        auto *searchResults=new QPlainTextEdit(panel);
        searchResults->setObjectName("DebuggerMemorySearchResults");
        searchResults->setReadOnly(true);
        searchResults->setMaximumHeight(175);
        connect(searchButton,&QPushButton::clicked,this,[this,memoryAddress,memoryPattern]{
            if(!debugSession_ || !debugSession_->running())return;
            QString value=memoryAddress->text().trimmed();
            if(value.startsWith("0x",Qt::CaseInsensitive))value=value.mid(2);
            bool ok=false;const quint64 address=value.toULongLong(&ok,16);
            if(!ok || !address){QMessageBox::warning(this,"Memory search","Enter a valid start address above.");return;}
            QString needle=memoryPattern->text();needle.remove(QRegularExpression("\\s+"));
            if(needle.isEmpty() || needle.size()%2 || needle.size()>256 || !QRegularExpression("^[0-9a-fA-F]+$").match(needle).hasMatch()){
                QMessageBox::warning(this,"Memory search","Enter 1–128 valid hexadecimal bytes.");return;
            }
            debugSession_->searchMemory(address,QByteArray::fromHex(needle.toLatin1()));
        });
        layout->addWidget(memoryPattern);
        layout->addWidget(searchButton);
        layout->addWidget(searchResults);
        auto *mapFilter=new QLineEdit(panel);
        mapFilter->setPlaceholderText("Filter memory map (e.g. RW-, Image, RIP)");
        layout->addWidget(mapFilter);
        auto mapSource=std::make_shared<QString>();
        connect(debugSession_,&WindowsDebugSession::memoryMapChanged,map,
            [map,mapSource,mapFilter](const QString &value){
                *mapSource=value;
                const QString pattern=mapFilter->text().trimmed();
                if(pattern.isEmpty()){map->setPlainText(value);return;}
                QStringList rows;for(const QString &line:value.split('\n'))
                    if(line.contains(pattern,Qt::CaseInsensitive))rows<<line;
                map->setPlainText(rows.join('\n'));
            },Qt::QueuedConnection);
        connect(mapFilter,&QLineEdit::textChanged,map,[map,mapSource](const QString &pattern){
            if(pattern.trimmed().isEmpty()){map->setPlainText(*mapSource);return;}
            QStringList rows;for(const QString &line:mapSource->split('\n'))
                if(line.contains(pattern,Qt::CaseInsensitive))rows<<line;
            map->setPlainText(rows.join('\n'));
        });
        layout->addWidget(new QLabel("Thread Explorer — paused snapshot",panel));
        layout->addWidget(threads);
        layout->addWidget(new QLabel("Module Explorer — paused snapshot",panel));
        layout->addWidget(modules);
        layout->addWidget(new QLabel("Register change history (latest 40 snapshots)",panel));
        layout->addWidget(history);
        layout->addWidget(log);
        layout->addWidget(continueButton);
        layout->addWidget(stepIntoButton);
        layout->addWidget(stepOverButton);
        layout->addWidget(toggleBreakpointButton);
        layout->addWidget(detachButton);
        // Re-organize existing controls into separately scrollable debugger pages.
        // All controls are created above; connections below retain their existing pointers.
        while (layout->count()>0) {
            QLayoutItem *item=layout->takeAt(0);
            if (QWidget *widget=item->widget()) {
                // The original label-only headings are superseded by section titles.
                if (qobject_cast<QLabel*>(widget) && widget!=state) widget->deleteLater();
            }
            // A QLayout is itself its QLayoutItem. Keep the memory toolbar
            // alive until it is moved to its new tab below.
            if (item!=memoryToolbar) delete item;
        }
        auto *header=new QHBoxLayout;
        header->addWidget(state,1);
        header->addWidget(continueButton);
        header->addWidget(stepIntoButton);
        header->addWidget(stepOverButton);
        header->addWidget(toggleBreakpointButton);
        header->addWidget(detachButton);
        layout->addLayout(header);
        auto *debugTabs=new QTabWidget(panel);
        debugTabs->setObjectName("DebuggerPageTabs");
        debugTabs->setDocumentMode(true);
        auto addPage=[debugTabs](const QString &name)->QVBoxLayout* {
            auto *container=new QWidget(debugTabs);
            auto *containerLayout=new QVBoxLayout(container);
            containerLayout->setContentsMargins(12,12,12,12);
            containerLayout->setSpacing(7);
            auto *scroller=new QScrollArea(debugTabs);
            scroller->setWidgetResizable(true);
            scroller->setFrameShape(QFrame::NoFrame);
            scroller->setWidget(container);
            debugTabs->addTab(scroller,name);
            return containerLayout;
        };
        auto *cpuPage=addPage("CPU / Assembly");
        cpuPage->addWidget(new QLabel("Live disassembly — RIP",panel));
        cpuPage->addWidget(disassembly);
        cpuPage->addWidget(new QLabel("Registers and flags",panel));
        cpuPage->addWidget(registers);
        cpuPage->addWidget(flags);
        cpuPage->addWidget(new QLabel("Software breakpoints",panel));
        cpuPage->addWidget(breakpoints);
        cpuPage->addStretch();
        auto *memoryPage=addPage("Memory / Map");
        memoryPage->addLayout(memoryToolbar);
        memoryPage->addWidget(dump);
        memoryPage->addWidget(new QLabel("HEX pattern search",panel));
        memoryPage->addWidget(memoryPattern);
        memoryPage->addWidget(searchButton);
        memoryPage->addWidget(searchResults);
        memoryPage->addWidget(new QLabel("Memory map filter",panel));
        memoryPage->addWidget(mapFilter);
        memoryPage->addWidget(map);
        memoryPage->addStretch();
        auto *stackPage=addPage("Stack / Trace");
        stackPage->addWidget(new QLabel("Current stack",panel));
        stackPage->addWidget(stack);
        stackPage->addWidget(new QLabel("DbgHelp call stack",panel));
        stackPage->addWidget(unwound);
        stackPage->addWidget(navigateCallStack);
        stackPage->addWidget(new QLabel("Return address candidates",panel));
        stackPage->addWidget(callstack);
        stackPage->addWidget(new QLabel("Register change history",panel));
        stackPage->addWidget(history);
        auto *traceHistory=new QPlainTextEdit(panel);
        traceHistory->setObjectName("DebuggerStopTrace");
        traceHistory->setReadOnly(true);
        traceHistory->setPlaceholderText("Debugger stop history appears here. Records only pauses, not all executed instructions.");
        traceHistory->setMinimumHeight(170);
        stackPage->addWidget(new QLabel("Bounded trace — last 512 stops/instructions",panel));
        auto *traceControls=new QHBoxLayout;
        auto *traceCount=new QSpinBox(panel);
        traceCount->setRange(1,1000);
        traceCount->setValue(50);
        traceCount->setToolTip("Max instruction steps for current paused thread (1–1000)");
        auto *traceField=new QComboBox(panel);
        traceField->setObjectName("DebuggerTraceStopField");
        traceField->addItems({"No condition","RIP","RAX","RSP","ZF"});
        auto *traceValue=new QLineEdit(panel);
        traceValue->setObjectName("DebuggerTraceStopValue");
        traceValue->setPlaceholderText("Hex value, e.g. 401000; ZF=0/1");
        traceValue->setEnabled(false);
        connect(traceField,&QComboBox::currentIndexChanged,traceValue,
            [traceValue](int index){traceValue->setEnabled(index>0);});
        auto *traceButton=new QPushButton("Trace / Until",panel);
        traceButton->setObjectName("DebuggerTraceInstructions");
        connect(traceButton,&QPushButton::clicked,this,[this,traceCount,traceField,traceValue]{
            if(!debugSession_ || !debugSession_->running())return;
            const QString field=traceField->currentIndex()==0?QString():traceField->currentText();
            quint64 value=0;
            if(!field.isEmpty()) {
                QString input=traceValue->text().trimmed();
                if(input.startsWith("0x",Qt::CaseInsensitive))input=input.mid(2);
                bool valid=false;
                value=input.toULongLong(&valid,field=="ZF"?10:16);
                if(!valid || (field=="ZF" && value>1)) {
                    QMessageBox::warning(this,"Trace condition","Enter a valid hex value (ZF: 0 or 1).");
                    return;
                }
            }
            debugSession_->traceUntil(static_cast<quint32>(traceCount->value()),field,value);
        });
        traceControls->addWidget(new QLabel("Max steps:",panel));
        traceControls->addWidget(traceCount);
        traceControls->addWidget(traceField);
        traceControls->addWidget(traceValue);
        traceControls->addWidget(traceButton);
        stackPage->addLayout(traceControls);
        auto *traceFilter=new QLineEdit(panel);
        traceFilter->setObjectName("DebuggerTraceFilter");
        traceFilter->setPlaceholderText("Filter trace by TID, RIP, cause or value...");
        stackPage->addWidget(traceFilter);
        stackPage->addWidget(traceHistory);
        auto traceRowsCache=std::make_shared<QStringList>();
        auto refreshTrace=[traceHistory,traceFilter,traceRowsCache](){
            const QString filter=traceFilter->text().trimmed();
            QStringList visible;
            for(const QString &row:*traceRowsCache)
                if(filter.isEmpty() || row.contains(filter,Qt::CaseInsensitive))visible<<row;
            traceHistory->setPlainText(visible.join('\n'));
        };
        connect(traceFilter,&QLineEdit::textChanged,traceHistory,
            [refreshTrace](const QString &){refreshTrace();});
        auto *traceGoTo=new QPushButton("Read selected trace RIP in Memory Dump",panel);
        traceGoTo->setObjectName("DebuggerTraceNavigate");
        connect(traceGoTo,&QPushButton::clicked,this,[this,traceHistory,memoryAddress]{
            if(!debugSession_ || !debugSession_->running())return;
            const QString row=traceHistory->textCursor().block().text();
            const QRegularExpression expression(QStringLiteral("RIP\\s+0x([0-9a-fA-F]{1,16})\\b"));
            const auto match=expression.match(row);
            if(!match.hasMatch()) {
                QMessageBox::information(this,"Trace navigation","Select a trace record containing a RIP address.");
                return;
            }
            bool ok=false;
            const quint64 address=match.captured(1).toULongLong(&ok,16);
            if(!ok || !address)return;
            memoryAddress->setText(QString::number(address,16).toUpper());
            debugSession_->requestMemory(address);
        });
        stackPage->addWidget(traceGoTo);
        stackPage->addStretch();
        auto *threadPage=addPage("Threads / Modules");
        threadPage->addWidget(threadPicker);
        threadPage->addWidget(inspectThreadButton);
        threadPage->addWidget(threads);
        threadPage->addWidget(modules);
        threadPage->addStretch();
        auto *logPage=addPage("Events / Snapshot");
        logPage->addWidget(log);
        auto *saveSnapshotButton=new QPushButton("Export debugger snapshot (JSON)",panel);
        saveSnapshotButton->setToolTip("Manual export: register, memory, stack and event data may be sensitive.");
        logPage->addWidget(saveSnapshotButton);
        auto *loadSnapshotButton=new QPushButton("Open offline snapshot (JSON)",panel);
        logPage->addWidget(loadSnapshotButton);
        connect(saveSnapshotButton,&QPushButton::clicked,this,
          [this,state,registers,flags,stack,disassembly,dump,map,threads,modules,history,traceHistory,unwound,callstack,breakpoints,log] {
            if (QMessageBox::question(this,"Export debugging information",
                "The snapshot may contain confidential process memory, register values and paths. "
                "Write these data into an unencrypted JSON file?",
                QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes) return;
            const QString path=QFileDialog::getSaveFileName(this,"Save debugger snapshot",{},"JSON (*.json)");
            if(path.isEmpty())return;
            const QJsonObject record{
              {"schema",QStringLiteral("yas-debug-snapshot-1")},
              {"timestampUtc",QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
              {"state",state->text()},
              {"registers",registers->toPlainText()},
              {"flags",flags->toPlainText()},
              {"stack",stack->toPlainText()},
              {"disassembly",disassembly->toPlainText()},
              {"memoryDump",dump->toPlainText()},
              {"memoryMap",map->toPlainText()},
              {"threads",threads->toPlainText()},
              {"modules",modules->toPlainText()},
              {"registerHistory",history->toPlainText()},
              {"debugStopTrace",traceHistory->toPlainText()},
              {"callStack",unwound->toPlainText()},
              {"returnCandidates",callstack->toPlainText()},
              {"breakpoints",breakpoints->toPlainText()},
              {"eventLog",log->toPlainText()}
            };
            QSaveFile file(path);
            if(!file.open(QIODevice::WriteOnly) ||
               file.write(QJsonDocument(record).toJson(QJsonDocument::Indented))<0 ||
               !file.commit()) {
                QMessageBox::warning(this,"Export failed","Cannot write JSON snapshot.");
            } else statusBar()->showMessage("Debugger snapshot saved",4000);
          });
        connect(loadSnapshotButton,&QPushButton::clicked,this,[this]{
            const QString path=QFileDialog::getOpenFileName(this,"Open debugger snapshot",{},"JSON (*.json)");
            if(path.isEmpty())return;
            QFile input(path);
            if(!input.open(QIODevice::ReadOnly) || input.size()>8*1024*1024){
                QMessageBox::warning(this,"Snapshot","Cannot open snapshot or file is larger than 8 MiB.");return;
            }
            QJsonParseError parseError;
            const auto doc=QJsonDocument::fromJson(input.readAll(),&parseError);
            if(parseError.error!=QJsonParseError::NoError || !doc.isObject() ||
               doc.object().value("schema").toString()!=QStringLiteral("yas-debug-snapshot-1")) {
                QMessageBox::warning(this,"Snapshot","Unrecognized or invalid snapshot.");return;
            }
            // Read-only independent preview; never changes a running debugger session.
            auto *viewer=new QDialog(this);
            viewer->setWindowTitle("Offline Debugger Snapshot — "+QFileInfo(path).fileName());
            viewer->resize(900,650);
            viewer->setAttribute(Qt::WA_DeleteOnClose);
            auto *viewerLayout=new QVBoxLayout(viewer);
            auto *snapshotTabs=new QTabWidget(viewer);
            const auto record=doc.object();
            const QStringList sections={"state","registers","flags","stack","disassembly",
                "memoryDump","memoryMap","threads","modules","registerHistory",
                "callStack","returnCandidates","breakpoints","eventLog"};
            for(const QString &key:sections){
                auto *field=new QPlainTextEdit(snapshotTabs);
                field->setReadOnly(true);
                field->setPlainText(record.value(key).toString());
                snapshotTabs->addTab(field,key);
            }
            viewerLayout->addWidget(snapshotTabs);
            viewer->show();
          });
        auto *conditionButton=new QPushButton("Set Breakpoint Condition (RIP/RAX/RSP/ZF)",panel);
        conditionButton->setToolTip("Choose to stop on all hits or automatically resume when the condition does not match.");
        connect(conditionButton,&QPushButton::clicked,this,[this]{
            if(!debugSession_ || !debugSession_->running())return;
            bool accepted=false;
            QString addressText=QInputDialog::getText(this,"Breakpoint condition","Existing breakpoint VA (hex):",
                QLineEdit::Normal,{},&accepted).trimmed();
            if(!accepted || addressText.isEmpty())return;
            if(addressText.startsWith("0x",Qt::CaseInsensitive))addressText=addressText.mid(2);
            const quint64 address=addressText.toULongLong(&accepted,16);
            if(!accepted || address==0){QMessageBox::warning(this,"Breakpoint","Invalid address.");return;}
            const QStringList fields={"RIP","RAX","RSP","ZF","Clear condition"};
            const QString field=QInputDialog::getItem(this,"Breakpoint condition","Compare register:",fields,1,false,&accepted);
            if(!accepted)return;
            if(field=="Clear condition"){
                debugSession_->configureBreakpointCondition(address,QString(),0);return;
            }
            QString valueText=QInputDialog::getText(this,"Breakpoint condition",
                field=="ZF"?"ZF value (0 or 1):":"Compare value (hex):",
                QLineEdit::Normal,{},&accepted).trimmed();
            if(!accepted || valueText.isEmpty())return;
            if(valueText.startsWith("0x",Qt::CaseInsensitive))valueText=valueText.mid(2);
            const quint64 value=valueText.toULongLong(&accepted,field=="ZF"?10:16);
            if(!accepted || (field=="ZF" && value>1)){
                QMessageBox::warning(this,"Breakpoint","Invalid condition value.");return;
            }
            const QStringList behavior={"Always pause (safe default)","Auto-continue when condition is false (experimental)"};
            const QString mode=QInputDialog::getItem(this,"Breakpoint behavior",
                "When the condition does not match:",behavior,0,false,&accepted);
            if(!accepted)return;
            const QString threadString=QInputDialog::getText(this,"Breakpoint thread filter",
                "Thread ID decimal (0 = any thread):",QLineEdit::Normal,"0",&accepted).trimmed();
            if(!accepted)return;
            bool validThread=false;
            const quint32 threadId=threadString.toUInt(&validThread,10);
            if(!validThread){QMessageBox::warning(this,"Breakpoint","Invalid thread ID.");return;}
            debugSession_->configureBreakpointCondition(address,field,value,mode==behavior[1],threadId);
        });
        layout->addWidget(conditionButton);
        layout->addWidget(debugTabs,1);
        dock->setMinimumWidth(580);
        dock->setWidget(panel);
        addDockWidget(Qt::BottomDockWidgetArea,dock);
        connect(continueButton,&QPushButton::clicked,debugSession_,&WindowsDebugSession::resume);
        connect(stepIntoButton,&QPushButton::clicked,debugSession_,&WindowsDebugSession::stepInto);
        connect(stepOverButton,&QPushButton::clicked,debugSession_,&WindowsDebugSession::stepOver);
        connect(toggleBreakpointButton,&QPushButton::clicked,this,[this]{
            bool ok=false;
            QString value=QInputDialog::getText(this,"Breakpoint (VA)","Hex address:",
                QLineEdit::Normal,{},&ok).trimmed();
            if(!ok||value.isEmpty())return;
            if(value.startsWith("0x",Qt::CaseInsensitive))value=value.mid(2);
            quint64 address=value.toULongLong(&ok,16);
            if(ok&&address&&debugSession_)debugSession_->toggleBreakpoint(address);
            else QMessageBox::warning(this,"Breakpoint","Invalid virtual address.");
        });
        connect(detachButton,&QPushButton::clicked,debugSession_,&WindowsDebugSession::stop);
        connect(debugSession_,&WindowsDebugSession::logLine,log,&QPlainTextEdit::appendPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::registersChanged,registers,
            [registers,previous=QString()](const QString &current) mutable {
                const QStringList oldLines=previous.split('\n');
                registers->setPlainText(current);
                const QStringList newLines=current.split('\n');
                for(int i=0;i<newLines.size();++i){
                    if(i>=oldLines.size() || newLines[i]!=oldLines[i]){
                        QTextCursor cursor(registers->document()->findBlockByNumber(i));
                        cursor.select(QTextCursor::LineUnderCursor);
                        QTextCharFormat format;
                        format.setForeground(QColor("#fbbf24"));
                        cursor.mergeCharFormat(format);
                    }
                }
                previous=current;
            },Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::registersChanged,history,
            [history,previous=QString(),snapshots=QStringList(),sequence=0](const QString &current) mutable {
                QStringList changes;
                const QStringList oldLines=previous.split('\n');
                const QStringList newLines=current.split('\n');
                for(int i=0;i<newLines.size();++i) {
                    if(previous.isEmpty() || i>=oldLines.size() || newLines[i]!=oldLines[i])
                        changes<<newLines[i];
                }
                previous=current;
                snapshots<<QString("#%1\n%2").arg(++sequence).arg(changes.join('\n'));
                while(snapshots.size()>40)snapshots.removeFirst();
                history->setPlainText(snapshots.join("\n---\n"));
            },Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::threadListChanged,threads,
            &QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::moduleListChanged,modules,
            &QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::debugStopTraceChanged,traceHistory,
            [traceRowsCache,refreshTrace](const QStringList &rows){
                *traceRowsCache=rows;
                refreshTrace();
            },Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::stackChanged,stack,&QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::cpuFlagsChanged,flags,&QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::memoryDumpChanged,dump,&QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::memorySearchResults,searchResults,
            &QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::callStackUnwoundChanged,unwound,
            &QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::callStackCandidatesChanged,callstack,
            &QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::stateChanged,state,&QLabel::setText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::disassemblyChanged,disassembly,
                &QPlainTextEdit::setPlainText,Qt::QueuedConnection);
        connect(debugSession_,&WindowsDebugSession::breakpointsChanged,breakpoints,
                [breakpoints](const QStringList &items){breakpoints->setPlainText(items.join('\n'));},Qt::QueuedConnection);
    }
    dock->show();
    dock->raise();
    debugSession_->launch(path);
#endif
}
