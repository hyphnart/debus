#include "WindowsDebugSession.h"
#include <QCoreApplication>
#include <QTimer>
#include <QDebug>
#include <QFileInfo>
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    if(argc<2){qCritical()<<"Missing debug target";return 2;}
    const QString target=QFileInfo(QString::fromLocal8Bit(argv[1])).absoluteFilePath();
    WindowsDebugSession debugger;
    bool paused=false;
    bool sawRegisters=false;
    bool failed=false;
    QObject::connect(&debugger,&WindowsDebugSession::registersChanged,&app,
        [&](const QString &registers){sawRegisters=!registers.isEmpty();});
    QObject::connect(&debugger,&WindowsDebugSession::stateChanged,&app,
        [&](const QString &state){
            qInfo()<<state;
            if(state.contains("Launch failed")||state=="Unavailable") {failed=true;app.quit();}
            else if(state.startsWith("Paused")) {paused=true;debugger.stop();app.quit();}
        });
    QObject::connect(&debugger,&WindowsDebugSession::logLine,&app,
        [](const QString &line){qInfo().noquote()<<line;});
    QTimer::singleShot(12000,&app,[&](){failed=true;debugger.stop();app.quit();});
    debugger.launch(target);
    app.exec();
    debugger.stop();
    if(failed||!paused||!sawRegisters){qCritical()<<"FAIL debugger initial break test";return 1;}
    qInfo()<<"PASS debugger initial break and register snapshot";
    return 0;
}
