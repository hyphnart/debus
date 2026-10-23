#include "BreakpointManagerDialog.h"
#include "WindowsDebugSession.h"
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSaveFile>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSet>
#include <limits>
namespace {
QString formatAddress(quint64 value){return QString("0x%1").arg(value,0,16).toUpper();}
bool parseHex(QString text,quint64 &value){
    text=text.trimmed();
    if(text.startsWith("0x",Qt::CaseInsensitive))text=text.mid(2);
    if(text.isEmpty()||text.size()>16)return false;
    for(const auto c:text){
        const ushort n=c.unicode();
        if(!((n>='0'&&n<='9')||(n>='a'&&n<='f')||(n>='A'&&n<='F')))return false;
    }
    bool ok=false;value=text.toULongLong(&ok,16);return ok;
}
}
BreakpointManagerDialog::BreakpointManagerDialog(WindowsDebugSession *session,QWidget *parent)
    :QDialog(parent),session_(session){
    setWindowTitle("Breakpoint Manager — Presets");
    resize(920,560);
    auto *layout=new QVBoxLayout(this);
    layout->addWidget(new QLabel("Saved definitions do not modify the running process. Arm one breakpoint at a time while paused.",this));
    table_=new QTableWidget(this);
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({"Virtual address","Condition","Value","Thread ID","On mismatch"});
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->verticalHeader()->setVisible(false);
    layout->addWidget(table_);
    auto *row=new QHBoxLayout;
    auto add=[this,row](const QString &label,void (BreakpointManagerDialog::*method)()){
        auto *b=new QPushButton(label,this);
        connect(b,&QPushButton::clicked,this,method);
        row->addWidget(b);
    };
    add("Add",&BreakpointManagerDialog::addEntry);
    add("Edit",&BreakpointManagerDialog::editEntry);
    add("Remove",&BreakpointManagerDialog::removeEntry);
    add("Import JSON",&BreakpointManagerDialog::importJson);
    add("Export JSON",&BreakpointManagerDialog::exportJson);
    layout->addLayout(row);
    auto *liveRow=new QHBoxLayout;
    auto *arm=new QPushButton("Toggle selected in debugger (F2)",this);
    auto *configure=new QPushButton("Apply condition to existing breakpoint",this);
    liveRow->addWidget(arm);
    liveRow->addWidget(configure);
    layout->addLayout(liveRow);
    connect(arm,&QPushButton::clicked,this,&BreakpointManagerDialog::armSelected);
    connect(configure,&QPushButton::clicked,this,&BreakpointManagerDialog::configureSelected);
    status_=new QLabel("Offline preset editor. Import/export JSON does not execute a target.",this);
    status_->setWordWrap(true);
    layout->addWidget(status_);
    auto *done=new QDialogButtonBox(QDialogButtonBox::Close,this);
    connect(done,&QDialogButtonBox::rejected,this,&QDialog::reject);
    layout->addWidget(done);
    updateTable();
}
int BreakpointManagerDialog::selectedIndex()const{
    const int i=table_->currentRow();return (i>=0 && i<presets_.size())?i:-1;
}
void BreakpointManagerDialog::updateTable(){
    table_->setRowCount(presets_.size());
    for(int i=0;i<presets_.size();++i){
        const auto &p=presets_[i];
        const QStringList columns={formatAddress(p.address),p.field.isEmpty()?"None":p.field,
           formatAddress(p.value),QString::number(p.threadId),p.skipUnmatched?"Auto-continue (experimental)":"Always pause"};
        for(int col=0;col<columns.size();++col)
            table_->setItem(i,col,new QTableWidgetItem(columns[col]));
    }
    table_->resizeColumnsToContents();
}
bool BreakpointManagerDialog::editPreset(BreakpointPreset &preset){
    QDialog dialog(this);
    dialog.setWindowTitle("Breakpoint Definition");
    auto *layout=new QFormLayout(&dialog);
    auto *address=new QLineEdit(formatAddress(preset.address),&dialog);
    auto *field=new QComboBox(&dialog);
    field->addItems({"None","RIP","RAX","RSP","ZF"});
    field->setCurrentText(preset.field.isEmpty()?"None":preset.field);
    auto *value=new QLineEdit(formatAddress(preset.value),&dialog);
    auto *thread=new QLineEdit(QString::number(preset.threadId),&dialog);
    auto *skip=new QCheckBox("Auto-continue when unmatched (experimental)",&dialog);
    skip->setChecked(preset.skipUnmatched);
    layout->addRow("Address (HEX)",address);
    layout->addRow("Condition",field);
    layout->addRow("Compare value (HEX)",value);
    layout->addRow("Thread ID (decimal; 0=any)",thread);
    layout->addRow("Behavior",skip);
    auto *buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel,&dialog);
    layout->addRow(buttons);
    connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
    connect(buttons,&QDialogButtonBox::accepted,&dialog,[&]{
        BreakpointPreset next;
        if(!parseHex(address->text(),next.address) || next.address==0 ||
           !parseHex(value->text(),next.value)){
            QMessageBox::warning(&dialog,"Invalid preset","Address/value must be hexadecimal; address must be nonzero.");return;
        }
        bool ok=false;
        next.threadId=thread->text().trimmed().toUInt(&ok,10);
        if(!ok){QMessageBox::warning(&dialog,"Invalid preset","Thread ID must be a 32-bit unsigned decimal integer.");return;}
        next.field=field->currentText()=="None"?QString():field->currentText();
        if(next.field=="ZF" && next.value>1){QMessageBox::warning(&dialog,"Invalid preset","ZF must be 0 or 1.");return;}
        next.skipUnmatched=skip->isChecked();
        for(const auto &item:presets_){
            if(item.address==next.address && item.address!=preset.address){
                QMessageBox::warning(&dialog,"Duplicate address","This breakpoint address already exists.");return;
            }
        }
        preset=next;
        dialog.accept();
    });
    return dialog.exec()==QDialog::Accepted;
}
void BreakpointManagerDialog::addEntry(){
    BreakpointPreset item;
    if(editPreset(item)){presets_.append(item);updateTable();}
}
void BreakpointManagerDialog::editEntry(){
    const int i=selectedIndex();if(i<0)return;
    BreakpointPreset changed=presets_[i];
    if(editPreset(changed)){presets_[i]=changed;updateTable();table_->selectRow(i);}
}
void BreakpointManagerDialog::removeEntry(){
    const int i=selectedIndex();if(i<0)return;
    presets_.removeAt(i);updateTable();
}
void BreakpointManagerDialog::importJson(){
    const QString path=QFileDialog::getOpenFileName(this,"Import breakpoint presets",{},"JSON (*.json)");
    if(path.isEmpty())return;
    QFile file(path);
    if(!file.open(QIODevice::ReadOnly)){
        QMessageBox::warning(this,"Import",file.errorString());return;
    }
    if(file.size()>1024*1024){QMessageBox::warning(this,"Import","Preset file exceeds 1 MiB.");return;}
    QVector<BreakpointPreset> parsed;QString error;
    if(!BreakpointPresetCodec::decode(file.readAll(),parsed,error)){
        QMessageBox::warning(this,"Import",error);return;
    }
    presets_=std::move(parsed);updateTable();
    status_->setText(QString("Loaded %1 definitions; none were automatically armed.").arg(presets_.size()));
}
void BreakpointManagerDialog::exportJson(){
    const QString path=QFileDialog::getSaveFileName(this,"Export breakpoint presets","breakpoints.json","JSON (*.json)");
    if(path.isEmpty())return;
    QSaveFile file(path);
    if(!file.open(QIODevice::WriteOnly)){
        QMessageBox::warning(this,"Export",file.errorString());return;
    }
    const QByteArray content=BreakpointPresetCodec::encode(presets_);
    if(file.write(content)!=content.size() || !file.commit()){
        QMessageBox::warning(this,"Export","Could not safely save JSON file.");return;
    }
    status_->setText(QString("Saved %1 definitions.").arg(presets_.size()));
}
void BreakpointManagerDialog::armSelected(){
    const int i=selectedIndex();if(i<0)return;
    if(!session_ || !session_->running()){
        QMessageBox::information(this,"Debugger","Launch and pause a debugger session first.");return;
    }
    session_->toggleBreakpoint(presets_[i].address);
    status_->setText("Toggle requested. Check the live breakpoint log; this button adds OR removes a breakpoint.");
}
void BreakpointManagerDialog::configureSelected(){
    const int i=selectedIndex();if(i<0)return;
    if(!session_ || !session_->running()){
        QMessageBox::information(this,"Debugger","Launch and pause a debugger session first.");return;
    }
    const auto &p=presets_[i];
    session_->configureBreakpointCondition(p.address,p.field,p.value,p.skipUnmatched,p.threadId);
    status_->setText("Condition requested. Breakpoint must already exist; confirm success in the live event log.");
}
