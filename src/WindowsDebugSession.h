#pragma once
#include <QObject>
#include <QString>
#include <QByteArray>
#include <QStringList>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <cstdint>

// Win32 debugger thread owns all debug events and process/thread handles.
// A command is accepted only when stopped on a debug exception.
class WindowsDebugSession final : public QObject {
    Q_OBJECT
public:
    explicit WindowsDebugSession(QObject *parent=nullptr);
    ~WindowsDebugSession() override;
    bool running() const {return running_.load();}
    void launch(const QString &path);
    void resume();
    void stepInto();
    void stepOver();
    void traceInstructions(quint32 count);
    void traceUntil(quint32 maximumSteps, const QString &field, quint64 equals);
    void toggleBreakpoint(quint64 address);
    void configureBreakpointCondition(quint64 address,const QString &field,quint64 equals,bool autoContinue=false,quint32 threadId=0);
    void requestBreak();
    void requestMemory(quint64 address);
    void inspectThread(quint32 threadId);
    void searchMemory(quint64 address,const QByteArray &pattern);
    void stop();
signals:
    void logLine(const QString &message);
    void stateChanged(const QString &state);
    void registersChanged(const QString &registers);
    void stackChanged(const QString &stack);
    void disassemblyChanged(const QString &disassembly);
    void breakpointsChanged(const QStringList &breakpoints);
    void instructionPointerChanged(quint64 address);
    void memoryMapChanged(const QString &map);
    void memoryDumpChanged(const QString &dump);
    void cpuFlagsChanged(const QString &flags);
    void threadListChanged(const QString &threads);
    void moduleListChanged(const QString &modules);
    void memorySearchResults(const QString &results);
    void callStackCandidatesChanged(const QString &stack);
    void callStackUnwoundChanged(const QString &stack);
    void debugStopTraceChanged(const QStringList &rows);
private:
    enum class Command { None, Continue, Into, Over, Trace, Toggle, ConfigureBreakpoint, ReadMemory, InspectThread, SearchMemory, Stop };
    void send(Command command,quint64 address=0);
    void run(QString path);
    std::thread thread_;
    std::atomic_bool running_{false};
    std::atomic_bool stopping_{false};
    std::mutex mutex_;
    std::condition_variable cv_;
    Command pending_=Command::None;
    quint64 pendingAddress_=0;
    QString pendingTraceField_;
    quint64 pendingTraceValue_=0;
    bool pendingAutoContinue_=false;
    quint32 pendingConditionThread_=0;
    QByteArray pendingPattern_;
};
