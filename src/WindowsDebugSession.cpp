#include "DebugTraceHistory.h"
#include "TraceStopCondition.h"
#include "ConditionalBreakpointPolicy.h"
#include "BreakpointDecision.h"
#include "WindowsDebugSession.h"
#include <QFileInfo>
#include <QDir>
#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <map>
#include <vector>
#include <array>
#include <algorithm>
#include <QByteArray>
#ifdef YAS_HAS_CAPSTONE
#include <capstone/capstone.h>
#endif
#include <QStringList>
namespace {
QString winError(DWORD code){return QString("Win32 error %1").arg(code);}
// During a software breakpoint's one-instruction restore window, keep other
// known threads from executing the temporarily unpatched address.  Handles are
// always resumed/closed (including error and detach paths). This is a bounded
// mitigation, not a complete solution for threads created during the window.
class OtherThreadHold {
public:
    OtherThreadHold()=default;
    ~OtherThreadHold(){release();}
    OtherThreadHold(const OtherThreadHold&)=delete;
    OtherThreadHold& operator=(const OtherThreadHold&)=delete;
    bool acquire(DWORD pid,DWORD eventTid) {
        release();
        HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
        if(snapshot==INVALID_HANDLE_VALUE)return false;
        THREADENTRY32 te={};te.dwSize=sizeof(te);
        bool ok=true;
        if(Thread32First(snapshot,&te))do {
            if(te.th32OwnerProcessID!=pid || te.th32ThreadID==eventTid)continue;
            HANDLE h=OpenThread(THREAD_SUSPEND_RESUME,FALSE,te.th32ThreadID);
            if(!h){ok=false;break;}
            if(SuspendThread(h)==static_cast<DWORD>(-1)) {
                CloseHandle(h);ok=false;break;
            }
            handles_.push_back(h);
        }while(Thread32Next(snapshot,&te));
        CloseHandle(snapshot);
        if(!ok)release();
        return ok;
    }
    void release() noexcept {
        for(auto it=handles_.rbegin();it!=handles_.rend();++it) {
            ResumeThread(*it);
            CloseHandle(*it);
        }
        handles_.clear();
    }
    bool active()const{return !handles_.empty();}
private:
    std::vector<HANDLE> handles_;
};

#ifdef _WIN64
bool readContext(DWORD tid,CONTEXT &ctx,HANDLE &thread) {
    thread=OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,tid);
    if(!thread)return false;
    ctx={};ctx.ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER;
    if(GetThreadContext(thread,&ctx))return true;
    CloseHandle(thread);thread=nullptr;return false;
}
QString formatContext(const CONTEXT &c){
    return QString("RIP: %1    RSP: %2\nRAX: %3    RBX: %4\nRCX: %5    RDX: %6\nRSI: %7    RDI: %8\nRBP: %9    RFLAGS: %10")
        .arg(c.Rip,16,16,QChar('0')).arg(c.Rsp,16,16,QChar('0'))
        .arg(c.Rax,16,16,QChar('0')).arg(c.Rbx,16,16,QChar('0'))
        .arg(c.Rcx,16,16,QChar('0')).arg(c.Rdx,16,16,QChar('0'))
        .arg(c.Rsi,16,16,QChar('0')).arg(c.Rdi,16,16,QChar('0'))
        .arg(c.Rbp,16,16,QChar('0')).arg(c.EFlags,8,16,QChar('0')).toUpper();
}
QString readStack(HANDLE process,quint64 rsp) {
    QStringList lines;
    for(int i=0;i<16;++i) {
        const quint64 address=rsp+static_cast<quint64>(i)*8;
        quint64 value=0;SIZE_T transferred=0;
        if(!ReadProcessMemory(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(address)),
                              &value,sizeof(value),&transferred) || transferred!=sizeof(value))break;
        lines<<QString("%1  %2").arg(address,16,16,QChar('0')).arg(value,16,16,QChar('0')).toUpper();
    }
    return lines.isEmpty()?QStringLiteral("Stack unavailable"):lines.join('\n');
}
QString decodeLive(HANDLE process,quint64 address) {
    constexpr SIZE_T byteLimit=96;
    std::array<unsigned char,byteLimit> bytes{};
    SIZE_T count=0;
    if(!ReadProcessMemory(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(address)),
                          bytes.data(),bytes.size(),&count) || count==0)
        return QString("Cannot read executable memory at 0x%1").arg(address,0,16);
#ifdef YAS_HAS_CAPSTONE
    csh capstone=0;
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&capstone)==CS_ERR_OK) {
        cs_insn *instructions=nullptr;
        const size_t decoded=cs_disasm(capstone,bytes.data(),count,address,16,&instructions);
        QStringList text;
        for(size_t i=0;i<decoded;++i){
            const auto &ins=instructions[i];
            QString hex=QByteArray(reinterpret_cast<const char*>(ins.bytes),ins.size).toHex(' ').toUpper();
            text<<QString("%1  %2  %3 %4").arg(ins.address,16,16,QChar('0'))
                .arg(hex.leftJustified(23,' '))
                .arg(QString::fromLatin1(ins.mnemonic),QString::fromLatin1(ins.op_str));
        }
        if(instructions)cs_free(instructions,decoded);
        cs_close(&capstone);
        if(!text.isEmpty())return text.join('\n');
    }
#endif
    QStringList text;
    for(SIZE_T i=0;i<count;i+=16)
        text<<QString("%1  %2").arg(address+i,16,16,QChar('0'))
          .arg(QByteArray(reinterpret_cast<const char*>(bytes.data()+i),
              static_cast<qsizetype>(std::min<SIZE_T>(16,count-i))).toHex(' ').toUpper());
    return text.join('\n')+"\n(Capstone unavailable: showing raw bytes)";
}
QString protectionName(DWORD protect) {
    const DWORD base=protect&0xff;
    switch(base) {
        case PAGE_NOACCESS:return "---";
        case PAGE_READONLY:return "R--";
        case PAGE_READWRITE:return "RW-";
        case PAGE_WRITECOPY:return "RC-";
        case PAGE_EXECUTE:return "--X";
        case PAGE_EXECUTE_READ:return "R-X";
        case PAGE_EXECUTE_READWRITE:return "RWX";
        case PAGE_EXECUTE_WRITECOPY:return "RCX";
        default:return "???";
    }
}
QString memoryMap(HANDLE process,quint64 instructionPointer) {
    // Scan only committed regions around RIP and nearby address space, bounded by
    // a strict region cap; a complete map can be expensive for large processes.
    QStringList lines;
    lines<<"BASE              SIZE       PERMS  STATE     TYPE";
    SYSTEM_INFO info={};GetSystemInfo(&info);
    quint64 address=0;
    const quint64 maximum=reinterpret_cast<quintptr>(info.lpMaximumApplicationAddress);
    int shown=0,scanned=0;
    while(address<maximum && scanned<100000 && shown<256) {
        MEMORY_BASIC_INFORMATION mbi={};
        if(!VirtualQueryEx(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(address)),&mbi,sizeof(mbi)))break;
        const quint64 base=reinterpret_cast<quintptr>(mbi.BaseAddress);
        const quint64 size=static_cast<quint64>(mbi.RegionSize);
        if(size==0 || base>UINT64_MAX-size)break;
        const quint64 next=base+size;
        ++scanned;
        if(mbi.State==MEM_COMMIT && ((mbi.Protect & 0xff)!=PAGE_NOACCESS)) {
            const bool containsRip=instructionPointer>=base && instructionPointer<next;
            lines<<QString("%1  %2  %3  %4  %5%6")
                .arg(base,16,16,QChar('0')).arg(size,10,16,QChar('0'))
                .arg(protectionName(mbi.Protect),-5)
                .arg(mbi.State==MEM_COMMIT?"Commit":"Other",-9)
                .arg(mbi.Type==MEM_IMAGE?"Image":mbi.Type==MEM_MAPPED?"Mapped":"Private")
                .arg(containsRip?"  < RIP":"");
            ++shown;
        }
        if(next<=address)break;
        address=next;
    }
    lines<<QString("Showing up to 256 accessible committed regions; scan bounded to 100000 regions. %1 visited.").arg(scanned);
    return lines.join('\n');
}
QString memoryDump(HANDLE process,quint64 address) {
    QStringList lines;
    lines<<QString("Read-only dump at 0x%1 (max 256 bytes)").arg(address,0,16);
    // Query memory before attempting to read to avoid crossing inaccessible pages.
    MEMORY_BASIC_INFORMATION mbi={};
    if(!VirtualQueryEx(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(address)),&mbi,sizeof(mbi)) || mbi.State!=MEM_COMMIT)
        return "Memory unavailable or not committed.";
    const DWORD protection=mbi.Protect&0xff;
    if((mbi.Protect&PAGE_GUARD) || protection==PAGE_NOACCESS || protection==PAGE_EXECUTE)
        return "Memory is guarded or not readable.";
    const quint64 end=reinterpret_cast<quintptr>(mbi.BaseAddress)+static_cast<quint64>(mbi.RegionSize);
    if(end<=address)return "Invalid memory region.";
    constexpr SIZE_T limit=256;
    std::array<unsigned char,limit> data{};
    SIZE_T bytesRead=0;
    const SIZE_T request=static_cast<SIZE_T>(std::min<quint64>(limit,end-address));
    if(!ReadProcessMemory(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(address)),data.data(),request,&bytesRead) || !bytesRead)
        return "ReadProcessMemory failed.";
    for(SIZE_T i=0;i<bytesRead;i+=16){
        const SIZE_T n=std::min<SIZE_T>(16,bytesRead-i);
        QByteArray chunk(reinterpret_cast<const char*>(data.data()+i),static_cast<qsizetype>(n));
        QString ascii;ascii.reserve(static_cast<qsizetype>(n));
        for(unsigned char c:chunk) ascii+=c>=32&&c<127?QChar(c):QChar('.');
        lines<<QString("%1  %2  %3").arg(address+i,16,16,QChar('0'))
            .arg(QString::fromLatin1(chunk.toHex(' ').toUpper()).leftJustified(47,' '))
            .arg(ascii);
    }
    return lines.join('\n');
}
// DbgHelp is single-threaded. All Sym*/StackWalk64 calls stay on the debug-event thread.
// Symbol lookup is local-only; it never downloads symbols or runs target code.
QString unwoundCallStack(HANDLE process,HANDLE thread,const CONTEXT &snapshot,bool symbolsReady) {
    if(!symbolsReady)return "DbgHelp could not initialize symbols; stack unwind unavailable.";
    CONTEXT context=snapshot; // StackWalk64 mutates CONTEXT.
    STACKFRAME64 frame={};
    frame.AddrPC.Offset=context.Rip;
    frame.AddrPC.Mode=AddrModeFlat;
    frame.AddrFrame.Offset=context.Rbp;
    frame.AddrFrame.Mode=AddrModeFlat;
    frame.AddrStack.Offset=context.Rsp;
    frame.AddrStack.Mode=AddrModeFlat;
    QStringList result;
    result<<"DbgHelp unwind (up to 48 frames; may be incomplete):";
    DWORD64 previousPc=0,previousSp=0;
    for(int i=0;i<48;++i) {
        const DWORD64 pc=frame.AddrPC.Offset;
        const DWORD64 sp=frame.AddrStack.Offset;
        if(i>0 && (!pc || (pc==previousPc && sp==previousSp)))break;
        if(pc) {
            alignas(SYMBOL_INFO) std::array<char,sizeof(SYMBOL_INFO)+MAX_SYM_NAME+1> storage{};
            auto *symbol=reinterpret_cast<SYMBOL_INFO*>(storage.data());
            symbol->SizeOfStruct=sizeof(SYMBOL_INFO);
            symbol->MaxNameLen=MAX_SYM_NAME;
            DWORD64 displacement=0;
            QString symbolText="(no local symbol)";
            if(SymFromAddr(process,pc,&displacement,symbol))
                symbolText=QString::fromLocal8Bit(symbol->Name)+QString(" +0x%1").arg(displacement,0,16);
            result<<QString("#%1  0x%2   %3").arg(i,2,10,QChar('0')).arg(pc,16,16,QChar('0')).arg(symbolText);
        }
        previousPc=pc;previousSp=sp;
        if(!StackWalk64(IMAGE_FILE_MACHINE_AMD64,process,thread,&frame,&context,
                        nullptr,SymFunctionTableAccess64,SymGetModuleBase64,nullptr))break;
    }
    if(result.size()==1)result<<"No unwind frames found.";
    return result.join('\n');
}
QString stackCandidates(HANDLE process,quint64 rsp) {
    QStringList lines;
    lines<<"Possible return addresses (heuristic only, not an unwound call stack):";
    for(int i=0;i<64;++i) {
        if(rsp>UINT64_MAX-static_cast<quint64>(i)*8)break;
        const quint64 slot=rsp+static_cast<quint64>(i)*8;
        quint64 value=0;SIZE_T received=0;
        if(!ReadProcessMemory(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(slot)),&value,8,&received) || received!=8)break;
        MEMORY_BASIC_INFORMATION mbi={};
        if(!VirtualQueryEx(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(value)),&mbi,sizeof(mbi)))continue;
        const DWORD protect=mbi.Protect&0xff;
        const bool executable=(protect==PAGE_EXECUTE || protect==PAGE_EXECUTE_READ ||
            protect==PAGE_EXECUTE_READWRITE || protect==PAGE_EXECUTE_WRITECOPY);
        if(executable && mbi.State==MEM_COMMIT && !(mbi.Protect&PAGE_GUARD))
            lines<<QString("[RSP+0x%1]  0x%2")
                .arg(i*8,0,16).arg(value,16,16,QChar('0'));
    }
    if(lines.size()==1)lines<<"No executable pointers found in first 64 stack entries.";
    return lines.join('\n');
}
QString boundedMemorySearch(HANDLE process,quint64 start,const QByteArray &needle) {
    if(needle.isEmpty() || needle.size()>128)return "Pattern must have 1–128 bytes.";
    MEMORY_BASIC_INFORMATION mbi={};
    if(!VirtualQueryEx(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(start)),&mbi,sizeof(mbi)) || mbi.State!=MEM_COMMIT)
        return "Start address is not committed.";
    const DWORD protect=mbi.Protect&0xff;
    if((mbi.Protect&PAGE_GUARD) || protect==PAGE_NOACCESS || protect==PAGE_EXECUTE)
        return "Region is not readable.";
    const quint64 base=static_cast<quint64>(reinterpret_cast<quintptr>(mbi.BaseAddress));
    if(mbi.RegionSize>UINT64_MAX-base)return "Invalid region size.";
    const quint64 end=base+static_cast<quint64>(mbi.RegionSize);
    if(end<=start)return "Invalid start address.";
    const quint64 span=std::min<quint64>(end-start,1024*1024);
    QByteArray bytes(static_cast<qsizetype>(span),'\0');
    SIZE_T read=0;
    if(!ReadProcessMemory(process,reinterpret_cast<LPCVOID>(static_cast<quintptr>(start)),bytes.data(),static_cast<SIZE_T>(span),&read) || !read)
        return "ReadProcessMemory could not read the region.";
    bytes.resize(static_cast<qsizetype>(read));
    QStringList results;
    results<<QString("Searching %1 bytes at 0x%2 (one readable region; max 1 MiB)").arg(read).arg(start,0,16);
    qsizetype position=0;int matches=0;
    while((position=bytes.indexOf(needle,position))>=0 && matches<200) {
        results<<QString("0x%1").arg(start+static_cast<quint64>(position),16,16,QChar('0'));
        ++matches;++position;
    }
    results<<QString("%1 match(es)%2").arg(matches).arg(matches==200?" (truncated)":"");
    return results.join('\n');
}
QString enumerateThreads(DWORD pid,DWORD stoppedTid) {
    QStringList entries;
    entries<<"TID       OWNER PID    STATE";
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snapshot==INVALID_HANDLE_VALUE)return "Thread snapshot unavailable.";
    THREADENTRY32 te={};te.dwSize=sizeof(te);
    if(Thread32First(snapshot,&te)){
        do {
            if(te.th32OwnerProcessID!=pid)continue;
            entries<<QString("%1    %2      %3")
                .arg(te.th32ThreadID,8,16,QChar('0'))
                .arg(pid,8,16,QChar('0'))
                .arg(te.th32ThreadID==stoppedTid?"Event thread":"Other thread");
        } while(Thread32Next(snapshot,&te));
    }
    CloseHandle(snapshot);
    return entries.join('\n');
}
QString enumerateModules(DWORD pid) {
    QStringList entries;
    entries<<"BASE              SIZE       MODULE";
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if(snapshot==INVALID_HANDLE_VALUE)return "Module snapshot unavailable.";
    MODULEENTRY32W me={};me.dwSize=sizeof(me);
    if(Module32FirstW(snapshot,&me)){
        int count=0;
        do{
            entries<<QString("%1  %2  %3")
                .arg(reinterpret_cast<quintptr>(me.modBaseAddr),16,16,QChar('0'))
                .arg(me.modBaseSize,8,16,QChar('0'))
                .arg(QString::fromWCharArray(me.szModule));
            if(++count>=512){entries<<"(truncated at 512 modules)";break;}
        }while(Module32NextW(snapshot,&me));
    }
    CloseHandle(snapshot);
    return entries.join('\n');
}
QString cpuFlags(DWORD value){
    struct Flag{const char *name;unsigned bit;};
    constexpr Flag flags[]={{"CF",0},{"PF",2},{"AF",4},{"ZF",6},{"SF",7},{"TF",8},{"IF",9},{"DF",10},{"OF",11}};
    QStringList lines;
    lines<<QString("EFLAGS: 0x%1").arg(value,8,16,QChar('0')).toUpper();
    for(const auto &flag:flags)
        lines<<QString("%1 = %2").arg(QString::fromLatin1(flag.name),-3).arg((value>>flag.bit)&1u);
    return lines.join("   ");
}
bool setTrap(HANDLE thread,CONTEXT &ctx) {
    ctx.EFlags|=0x100;
    return SetThreadContext(thread,&ctx)!=0;
}
bool patchByte(HANDLE process,quint64 address,unsigned char value,unsigned char *previous=nullptr) {
    const auto ptr=reinterpret_cast<LPVOID>(static_cast<quintptr>(address));
    unsigned char original=0;SIZE_T n=0;
    if(!ReadProcessMemory(process,ptr,&original,1,&n)||n!=1)return false;
    DWORD oldProtect=0;
    if(!VirtualProtectEx(process,ptr,1,PAGE_EXECUTE_READWRITE,&oldProtect))return false;
    n=0;
    const bool wrote=WriteProcessMemory(process,ptr,&value,1,&n)&&n==1;
    FlushInstructionCache(process,ptr,1);
    DWORD unused=0;
    VirtualProtectEx(process,ptr,1,oldProtect,&unused);
    if(wrote && previous)*previous=original;
    return wrote;
}
#endif
}
#endif
WindowsDebugSession::WindowsDebugSession(QObject *parent):QObject(parent){}
WindowsDebugSession::~WindowsDebugSession(){stop();}
void WindowsDebugSession::launch(const QString &path) {
    if(running_.exchange(true))return;
    if(thread_.joinable())thread_.join();
    stopping_.store(false);
    {std::lock_guard<std::mutex> lock(mutex_);pending_=Command::None;pendingAddress_=0;}
    thread_=std::thread([this,path]{run(path);});
}
void WindowsDebugSession::send(Command command,quint64 address) {
    if(!running_.load())return;
    {std::lock_guard<std::mutex> lock(mutex_);
        pending_=command;pendingAddress_=address;}
    cv_.notify_all();
}
void WindowsDebugSession::resume(){send(Command::Continue);}
void WindowsDebugSession::stepInto(){send(Command::Into);}
void WindowsDebugSession::stepOver(){send(Command::Over);}
void WindowsDebugSession::traceInstructions(quint32 count){traceUntil(count,QString(),0);}
void WindowsDebugSession::traceUntil(quint32 count,const QString &field,quint64 equals) {
    if(!running_.load())return;
    {std::lock_guard<std::mutex> lock(mutex_);
        pending_=Command::Trace;pendingAddress_=count;
        pendingTraceField_=field;pendingTraceValue_=equals;}
    cv_.notify_all();
}
void WindowsDebugSession::toggleBreakpoint(quint64 address){send(Command::Toggle,address);}
void WindowsDebugSession::configureBreakpointCondition(quint64 address,const QString &field,quint64 equals,bool autoContinue,quint32 threadId){
    if(!running_.load())return;
    {std::lock_guard<std::mutex> lock(mutex_);
        pending_=Command::ConfigureBreakpoint;pendingAddress_=address;
        pendingTraceField_=field;pendingTraceValue_=equals;pendingAutoContinue_=autoContinue;pendingConditionThread_=threadId;}
    cv_.notify_all();
}
void WindowsDebugSession::requestMemory(quint64 address){send(Command::ReadMemory,address);}
void WindowsDebugSession::inspectThread(quint32 threadId){send(Command::InspectThread,threadId);}
void WindowsDebugSession::searchMemory(quint64 address,const QByteArray &pattern){
    if(!running_.load())return;
    {std::lock_guard<std::mutex> lock(mutex_);
        pendingPattern_=pattern;pending_=Command::SearchMemory;pendingAddress_=address;}
    cv_.notify_all();
}
void WindowsDebugSession::requestBreak(){emit logLine("Pause-on-demand not yet supported. Use a breakpoint or Step Into.");}
void WindowsDebugSession::stop(){
    stopping_.store(true);
    {std::lock_guard<std::mutex> lock(mutex_);pending_=Command::Stop;}
    cv_.notify_all();
    if(thread_.joinable())thread_.join();
    running_.store(false);
}
void WindowsDebugSession::run(QString path){
#if defined(Q_OS_WIN) && defined(_WIN64)
    const QString absolute=QFileInfo(path).absoluteFilePath();
    if(!QFileInfo::exists(absolute)){
        emit logLine("Executable missing: "+absolute);
        emit stateChanged("Launch failed");running_=false;return;
    }
    STARTUPINFOW si={};si.cb=sizeof(si);
    PROCESS_INFORMATION pi={};
    std::wstring command=L"\""+QDir::toNativeSeparators(absolute).toStdWString()+L"\"";
    std::wstring working=QDir::toNativeSeparators(QFileInfo(absolute).absolutePath()).toStdWString();
    if(!CreateProcessW(absolute.toStdWString().c_str(),command.data(),nullptr,nullptr,FALSE,
                DEBUG_ONLY_THIS_PROCESS|CREATE_NEW_CONSOLE,nullptr,working.c_str(),&si,&pi)){
        emit logLine("CreateProcessW: "+winError(GetLastError()));
        emit stateChanged("Launch failed");running_=false;return;
    }
    CloseHandle(pi.hThread);
    const bool symbolsReady=SymInitialize(pi.hProcess,nullptr,TRUE)!=FALSE;
    if(symbolsReady) {
        SymSetOptions(SymGetOptions()|SYMOPT_UNDNAME|SYMOPT_DEFERRED_LOADS);
        emit logLine("DbgHelp local symbol resolution enabled.");
    } else emit logLine("DbgHelp initialization failed: "+winError(GetLastError()));
    emit logLine("Process launched. PID "+QString::number(pi.dwProcessId));
    emit stateChanged("Running PID "+QString::number(pi.dwProcessId));
    struct Breakpoint {unsigned char original=0;bool armed=false;bool temporary=false;};
    std::map<quint64,Breakpoint> breakpoints;
    auto notifyBreakpoints=[this,&breakpoints](){
        QStringList output;
        for(const auto &[address,bp]:breakpoints)
            output<<QString("0x%1  %2%3").arg(address,0,16)
               .arg(bp.armed?"Enabled":"Temporarily disarmed")
               .arg(bp.temporary?" (Step Over)":"");
        emit breakpointsChanged(output);
    };
    quint64 rearmAddress=0; // Reinsert original breakpoint after single step
    DWORD rearmThread=0;
    OtherThreadHold rearmIsolation;
    bool singleStepToPause=false;
    DWORD stepThread=0;
    quint32 traceRemaining=0;
    TraceStopCondition traceStop;
    std::map<quint64,ConditionalBreakpointPolicy> breakpointConditions;
    std::map<quint64,DWORD> breakpointThreadFilters;
    std::map<quint64,BreakpointStatistics> breakpointStatistics;
    std::map<quint64,std::uint64_t> breakpointHitCounts;
    DWORD traceThread=0;
    DebugTraceHistory stopHistory(512);
    auto publishTrace=[this,&stopHistory](){
        QStringList rows;
        rows.reserve(static_cast<qsizetype>(stopHistory.items().size()));
        for(const auto &entry:stopHistory.items()) {
            rows<<QString("#%1  TID %2  RIP 0x%3  RAX 0x%4  RSP 0x%5  %6")
                .arg(entry.sequence).arg(entry.thread)
                .arg(entry.instructionPointer,0,16).arg(entry.accumulator,0,16)
                .arg(entry.stackPointer,0,16).arg(QString::fromStdString(entry.cause));
        }
        emit debugStopTraceChanged(rows);
    };
    // Only the thread that initiated stepping may complete the pending step.
    bool firstLoaderBreak=true;
    bool alive=true;
    while(alive && !stopping_.load()) {
        DEBUG_EVENT event={};
        if(!WaitForDebugEvent(&event,100)){
            DWORD error=GetLastError();
            if(error!=ERROR_SEM_TIMEOUT){emit logLine("WaitForDebugEvent: "+winError(error));break;}
            continue;
        }
        DWORD disposition=DBG_CONTINUE;
        bool pause=false;
        DWORD tid=event.dwThreadId;
        bool atOurBreakpoint=false;
        quint64 bpAddress=0;
        CONTEXT ctx={};
        HANDLE thread=nullptr;
        if(event.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT) {
            if(event.u.CreateProcessInfo.hFile)CloseHandle(event.u.CreateProcessInfo.hFile);
            // Handle ownership belongs to debug event; process and thread handles are borrowed.
            emit logLine("CREATE_PROCESS");
        } else if(event.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT) {
            // Do not close the debug event's hThread; Windows owns its lifetime.
        } else if(event.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT) {
            if(event.u.LoadDll.hFile)CloseHandle(event.u.LoadDll.hFile);
        } else if(event.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT) {
            emit logLine(QString("Process exited: %1").arg(event.u.ExitProcess.dwExitCode));
            alive=false;
        } else if(event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT) {
            const DWORD exception=event.u.Exception.ExceptionRecord.ExceptionCode;
            const bool first=event.u.Exception.dwFirstChance!=0;
            if(exception==EXCEPTION_BREAKPOINT) {
                if(readContext(tid,ctx,thread)) {
                    const quint64 ip=ctx.Rip;
                    // INT3 is one byte, so RIP usually points to the following address.
                    if(ip>0) {
                        auto it=breakpoints.find(ip-1);
                        if(it!=breakpoints.end() && it->second.armed) {
                            bpAddress=ip-1;
                            atOurBreakpoint=true;
                            if(!patchByte(pi.hProcess,bpAddress,it->second.original)) {
                                emit logLine(QString("Cannot restore breakpoint byte at 0x%1").arg(bpAddress,0,16));
                                disposition=DBG_EXCEPTION_NOT_HANDLED;
                            } else {
                            CONTEXT restored=ctx;
                            restored.Rip=bpAddress;
                            if(!SetThreadContext(thread,&restored)) {
                                // Keep breakpoint state consistent when thread context update fails.
                                it->second.armed=patchByte(pi.hProcess,bpAddress,0xCC);
                                emit logLine(QString("Cannot rewind RIP at 0x%1").arg(bpAddress,0,16));
                                disposition=DBG_EXCEPTION_NOT_HANDLED;
                            } else {
                            it->second.armed=false;
                            ctx=restored;
                            pause=true;
                            if(it->second.temporary) {
                                breakpoints.erase(it);
                            } else {
                                rearmAddress=bpAddress;
                                rearmThread=tid;
                            }
                            notifyBreakpoints();
                            const auto hits=++breakpointHitCounts[bpAddress];
                            auto rule=breakpointConditions.find(bpAddress);
                            if(rule!=breakpointConditions.end()) {
                                DebugStopRecord hitRecord;
                                hitRecord.instructionPointer=restored.Rip;
                                hitRecord.accumulator=restored.Rax;
                                hitRecord.stackPointer=restored.Rsp;
                                hitRecord.flags=restored.EFlags;
                                const DWORD allowedThread=breakpointThreadFilters.contains(bpAddress)
                                    ? breakpointThreadFilters.at(bpAddress):0;
                                const BreakpointDecision decision=evaluateBreakpoint(
                                    rule->second.condition,hitRecord,
                                    static_cast<std::uint32_t>(allowedThread),
                                    static_cast<std::uint32_t>(tid),rule->second.skipUnmatched);
                                // Statistics are updated *after* the independent decision.
                                auto &stats=breakpointStatistics[bpAddress];
                                stats.record(decision);
                                const bool shouldStop=decision.shouldPause;
                                emit logLine(QString("Breakpoint 0x%1 hits=%2 threadMatched=%3 conditionMatched=%4 effectiveMatches=%5")
                                    .arg(bpAddress,0,16).arg(stats.hits)
                                    .arg(decision.threadMatched?"YES":"NO")
                                    .arg(decision.conditionMatched?"YES":"NO")
                                    .arg(stats.effectiveMatches));
                                if(!decision.threadMatched)emit logLine("Breakpoint thread filter mismatch.");
                                if(!shouldStop && rearmAddress==bpAddress) {
                                    // The debugger owns the INT3: restore, rewind, single-step once,
                                    // then rearm while peer threads are suspended.
                                    if(rearmIsolation.acquire(pi.dwProcessId,tid)) {
                                        CONTEXT stepping=restored;
                                        if(setTrap(thread,stepping)) {
                                            pause=false;
                                            ++stats.automaticContinues;
                                            emit logLine("Condition false: automatic continue (safe rearm pending).");
                                        } else {
                                            rearmIsolation.release();
                                            emit logLine("Trap flag failed; stopping instead of auto-continue.");
                                        }
                                    } else emit logLine("Thread isolation failed; stopping instead of auto-continue.");
                                }
                            } else {
                                emit logLine(QString("Breakpoint hit: 0x%1, total hits %2").arg(bpAddress,0,16).arg(hits));
                            }
                            }
                            }
                        }
                    }
                    CloseHandle(thread);thread=nullptr;
                }
                if(atOurBreakpoint && disposition==DBG_EXCEPTION_NOT_HANDLED) {
                    pause=false;
                }
                if(!atOurBreakpoint && firstLoaderBreak && first) {
                    firstLoaderBreak=false;
                    pause=true;
                    emit logLine("Initial loader breakpoint");
                } else if(!atOurBreakpoint) {
                    disposition=DBG_EXCEPTION_NOT_HANDLED;
                    emit logLine("Application-owned INT3 forwarded to target exception handlers.");
                }
            } else if(exception==EXCEPTION_SINGLE_STEP) {
                const bool maintenanceStep=(rearmAddress!=0 && rearmThread==tid);
                const bool traceStep=(traceRemaining>0 && traceThread==tid && !maintenanceStep);
                if(readContext(tid,ctx,thread)) {
                    if(rearmAddress && rearmThread==tid) {
                        auto it=breakpoints.find(rearmAddress);
                        if(it!=breakpoints.end() && !it->second.armed) {
                            if(!patchByte(pi.hProcess,rearmAddress,0xCC)) {
                                emit logLine(QString("WARNING: breakpoint rearm failed at 0x%1; left disabled").arg(rearmAddress,0,16));
                            } else it->second.armed=true;
                        }
                        rearmAddress=0;rearmThread=0;
                        rearmIsolation.release();
                    }
                    // Bounded trace: record the post-instruction RIP and registers.
                    // Only the selected thread advances the trace; no snapshot panels
                    // are refreshed for each intermediate step.
                    if(traceStep) {
                        DebugStopRecord record;
                        record.thread=tid;record.instructionPointer=ctx.Rip;
                        record.accumulator=ctx.Rax;record.stackPointer=ctx.Rsp;
                        record.flags=ctx.EFlags;record.cause="instruction-trace";
                        stopHistory.append(record);
                        --traceRemaining;
                        if(traceStop.matches(record)) {
                            traceRemaining=0;
                            emit logLine("Trace stopped: register/address condition matched.");
                        }
                    }
                    ctx.EFlags&=~static_cast<DWORD>(0x100);
                    if(traceStep && traceRemaining>0)ctx.EFlags|=0x100;
                    if(!SetThreadContext(thread,&ctx)) {
                        emit logLine("Cannot update trap flag: "+winError(GetLastError()));
                        disposition=DBG_EXCEPTION_NOT_HANDLED;
                        traceRemaining=0;traceThread=0;
                        pause=true;
                    }
                    CloseHandle(thread);thread=nullptr;
                    notifyBreakpoints();
                } else if(maintenanceStep) {
                    emit logLine("Cannot read context during breakpoint rearm; resuming held threads.");
                    rearmIsolation.release();
                    rearmAddress=0;rearmThread=0;
                    disposition=DBG_EXCEPTION_NOT_HANDLED;
                }
                const bool traceFinished=traceStep && traceRemaining==0;
                if(traceFinished){traceThread=0;publishTrace();}
                pause=(singleStepToPause && stepThread==tid && disposition==DBG_CONTINUE)
                    || traceFinished;
                if(stepThread==tid) {singleStepToPause=false;stepThread=0;}
                // Forward unexpected single-step exceptions rather than consuming
                // them as though they originated from our Step Into command.
                if(!pause && !maintenanceStep && !traceStep)
                    disposition=DBG_EXCEPTION_NOT_HANDLED;
            } else {
                disposition=DBG_EXCEPTION_NOT_HANDLED;
                emit logLine(QString("Exception %1 0x%2 (%3 chance)")
                     .arg(tid).arg(exception,8,16,QChar('0')).arg(first?"first":"second"));
            }
            if(pause && traceRemaining>0 && tid!=traceThread) {
                emit logLine("Trace aborted: another thread caused a debugger stop.");
                traceRemaining=0;
                traceThread=0;
            }
            if(pause) {
                if(readContext(tid,ctx,thread)){
                    DebugStopRecord stopRecord;
                    stopRecord.thread=tid;
                    stopRecord.instructionPointer=ctx.Rip;
                    stopRecord.accumulator=ctx.Rax;
                    stopRecord.stackPointer=ctx.Rsp;
                    stopRecord.flags=ctx.EFlags;
                    stopRecord.cause=atOurBreakpoint?"software-breakpoint":
                        exception==EXCEPTION_SINGLE_STEP?"single-step":"loader-breakpoint";
                    // The final trace step was recorded above. Avoid a duplicate.
                    if(!traceStep)stopHistory.append(stopRecord);
                    publishTrace();
                    emit registersChanged(formatContext(ctx));
                    emit stackChanged(readStack(pi.hProcess,ctx.Rsp));
                    emit callStackCandidatesChanged(stackCandidates(pi.hProcess,ctx.Rsp));
                    emit callStackUnwoundChanged(unwoundCallStack(pi.hProcess,thread,ctx,symbolsReady));
                    emit disassemblyChanged(decodeLive(pi.hProcess,ctx.Rip));
                    emit instructionPointerChanged(ctx.Rip);
                    emit memoryMapChanged(memoryMap(pi.hProcess,ctx.Rip));
                    emit memoryDumpChanged(memoryDump(pi.hProcess,ctx.Rip));
                    emit cpuFlagsChanged(cpuFlags(ctx.EFlags));
                    emit threadListChanged(enumerateThreads(pi.dwProcessId,tid));
                    emit moduleListChanged(enumerateModules(pi.dwProcessId));
                    CloseHandle(thread);thread=nullptr;
                }
            }
        }
        if(pause && !stopping_.load()){
            emit stateChanged("Paused — F9 continue, F7 step into, F8 step over");
            bool ready=false;
            while(!ready && !stopping_.load()){
                Command action=Command::None;quint64 address=0;QByteArray pattern;
                QString conditionField;quint64 conditionValue=0;bool autoContinue=false;quint32 conditionThread=0;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    cv_.wait(lock,[this]{return pending_!=Command::None || stopping_.load();});
                    action=pending_;address=pendingAddress_;pattern=pendingPattern_;
                    conditionField=pendingTraceField_;conditionValue=pendingTraceValue_;
                    autoContinue=pendingAutoContinue_;pendingAutoContinue_=false;
                    conditionThread=pendingConditionThread_;pendingConditionThread_=0;
                    pendingPattern_.clear();pendingTraceField_.clear();pendingTraceValue_=0;
                    pending_=Command::None;
                }
                if(action==Command::InspectThread){
                    HANDLE inspected=nullptr;CONTEXT inspectedContext={};
                    if(readContext(static_cast<DWORD>(address),inspectedContext,inspected)){
                        emit registersChanged(formatContext(inspectedContext));
                        emit stackChanged(readStack(pi.hProcess,inspectedContext.Rsp));
                        emit callStackCandidatesChanged(stackCandidates(pi.hProcess,inspectedContext.Rsp));
                        emit callStackUnwoundChanged(unwoundCallStack(pi.hProcess,inspected,inspectedContext,symbolsReady));
                        emit logLine(QString("Inspecting thread %1 (execution stepping still follows the event thread)").arg(address));
                        CloseHandle(inspected);
                    } else emit logLine("Cannot inspect the selected thread.");
                    continue;
                }
                if(action==Command::SearchMemory){
                    emit memorySearchResults(boundedMemorySearch(pi.hProcess,address,pattern));
                    continue;
                }
                if(action==Command::ReadMemory){
                    emit memoryDumpChanged(memoryDump(pi.hProcess,address));
                    emit logLine(QString("Read-only memory dump requested: 0x%1").arg(address,0,16));
                    continue;
                }
                if(action==Command::ConfigureBreakpoint){
                    if(!breakpoints.contains(address)) {
                        emit logLine("Add a normal breakpoint before setting its condition.");
                        continue;
                    }
                    TraceStopCondition rule;
                    const QString key=conditionField.trimmed().toUpper();
                    if(key=="RIP")rule.field=TraceStopCondition::Field::Rip;
                    else if(key=="RAX")rule.field=TraceStopCondition::Field::Rax;
                    else if(key=="RSP")rule.field=TraceStopCondition::Field::Rsp;
                    else if(key=="ZF")rule.field=TraceStopCondition::Field::Zf;
                    else if(key.isEmpty()) {
                        if(conditionThread==0 && !autoContinue) {
                            breakpointConditions.erase(address);
                            breakpointThreadFilters.erase(address);
                            emit logLine(QString("Breakpoint rule cleared: 0x%1").arg(address,0,16));
                            continue;
                        }
                        // A thread-only filter is valid; a register condition is optional.
                        rule.field=TraceStopCondition::Field::None;
                    } else {emit logLine("Unsupported breakpoint condition.");continue;}
                    if(key=="ZF" && conditionValue>1){
                        emit logLine("ZF must be 0 or 1.");continue;
                    }
                    rule.equals=conditionValue;
                    ConditionalBreakpointPolicy policy;
                    policy.condition=rule;
                    policy.skipUnmatched=autoContinue;
                    breakpointConditions[address]=policy;
                    breakpointThreadFilters[address]=conditionThread;
                    breakpointStatistics.erase(address);
                    emit logLine(QString("Breakpoint thread filter (0=any): %1").arg(conditionThread));
                    emit logLine(QString("Breakpoint condition set at 0x%1: %2 == 0x%3 (%4)")
                        .arg(address,0,16).arg(key).arg(conditionValue,0,16)
                        .arg(autoContinue?"auto-continue on mismatch":"always pause"));
                    continue;
                }
                if(action==Command::Toggle){
                    auto it=breakpoints.find(address);
                    if(it!=breakpoints.end()) {
                        bool removed=!it->second.armed;
                        if(it->second.armed)
                            removed=patchByte(pi.hProcess,address,it->second.original);
                        if(!removed) {
                            emit logLine(QString("Failed to remove breakpoint at 0x%1").arg(address,0,16));
                        } else {
                            breakpoints.erase(it);
                            breakpointConditions.erase(address);
                            breakpointThreadFilters.erase(address);
                            breakpointHitCounts.erase(address);
                            breakpointStatistics.erase(address);
                            emit logLine(QString("Breakpoint removed: 0x%1").arg(address,0,16));
                            if(rearmAddress==address){rearmAddress=0;rearmThread=0;}
                        }
                    } else {
                        // Adding at a currently stopped RIP is rejected: avoid executing a
                        // fresh INT3 immediately on resume before the instruction runs.
                        CONTEXT current={};HANDLE currentThread=nullptr;
                        bool isCurrentRip=false;
                        if(readContext(tid,current,currentThread)) {
                            isCurrentRip=(current.Rip==address);
                            CloseHandle(currentThread);
                        }
                        if(isCurrentRip){
                            emit logLine("Cannot arm breakpoint at current RIP; step once first.");
                            continue;
                        }
                        unsigned char original=0;
                        if(patchByte(pi.hProcess,address,0xCC,&original)){
                            breakpoints[address]={original,true,false};
                            emit logLine(QString("Breakpoint set: 0x%1").arg(address,0,16));
                        } else emit logLine(QString("Cannot set breakpoint at 0x%1").arg(address,0,16));
                    }
                    notifyBreakpoints();
                    continue;
                }
                if(action==Command::Stop)break;
                if(action==Command::Trace && rearmAddress!=0) {
                    emit logLine("Trace refused while a software breakpoint requires rearming. Step once first.");
                    continue;
                }
                if(action==Command::Continue || action==Command::Into ||
                   action==Command::Over || action==Command::Trace){
                    if(action==Command::Trace && (address==0 || address>1000)){
                        emit logLine("Trace length must be between 1 and 1000.");
                        continue;
                    }
                    const bool stepping=(action!=Command::Continue);
                    bool performTrap=stepping || rearmAddress!=0;
                    if(readContext(tid,ctx,thread)){
                        if(action==Command::Over && rearmAddress==0) {
                            unsigned char opcode=0;SIZE_T n=0;
                            if(ReadProcessMemory(pi.hProcess,
                                reinterpret_cast<LPCVOID>(static_cast<quintptr>(ctx.Rip)),
                                &opcode,1,&n) && n==1 && opcode==0xE8) {
                                const quint64 returnAddress=ctx.Rip+5;
                                if(!breakpoints.contains(returnAddress)){
                                    unsigned char original=0;
                                    if(patchByte(pi.hProcess,returnAddress,0xCC,&original)){
                                        breakpoints[returnAddress]={original,true,true};
                                        performTrap=false;
                                        notifyBreakpoints();
                                        emit logLine(QString("Step-over return breakpoint: 0x%1").arg(returnAddress,0,16));
                                    }
                                }
                            }
                        }
                        if(performTrap && !setTrap(thread,ctx)) {
                            emit logLine("SetThreadContext trap flag failed: "+winError(GetLastError()));
                            CloseHandle(thread);thread=nullptr;
                            continue;
                        }
                        CloseHandle(thread);thread=nullptr;
                    } else {
                        emit logLine("Unable to read event-thread context; resume aborted.");
                        continue;
                    }
                    // An INT3 that has been restored must be stepped through and reinserted;
                    // do not report this maintenance single-step as a user-visible pause.
                    // A restored INT3 requires one hidden single-step before re-arming.
                    // Stepping on a breakpoint resumes the original instruction first;
                    // then the event is delivered on the next stop.
                    if(rearmAddress!=0 && rearmThread==tid) {
                        if(!rearmIsolation.acquire(pi.dwProcessId,tid)) {
                            emit logLine("Unable to suspend peer threads for breakpoint maintenance; resume cancelled.");
                            // Re-arm the breakpoint immediately rather than exposing
                            // its original byte to running peer threads.
                            auto it=breakpoints.find(rearmAddress);
                            if(it!=breakpoints.end() && !it->second.armed) {
                                it->second.armed=patchByte(pi.hProcess,rearmAddress,0xCC);
                            }
                            // Reset TF before staying paused. RIP is still the breakpoint address;
                            // running remains blocked until the user explicitly intervenes.
                            HANDLE fixThread=nullptr;CONTEXT fixContext={};
                            if(readContext(tid,fixContext,fixThread)) {
                                fixContext.EFlags&=~static_cast<DWORD>(0x100);
                                SetThreadContext(fixThread,&fixContext);
                                CloseHandle(fixThread);
                            }
                            rearmAddress=0;rearmThread=0;
                            notifyBreakpoints();
                            continue;
                        }
                    }
                    if(action==Command::Trace){
                        traceStop={};
                        const QString field=conditionField.trimmed().toUpper();
                        if(field=="RIP")traceStop.field=TraceStopCondition::Field::Rip;
                        else if(field=="RAX")traceStop.field=TraceStopCondition::Field::Rax;
                        else if(field=="RSP")traceStop.field=TraceStopCondition::Field::Rsp;
                        else if(field=="ZF")traceStop.field=TraceStopCondition::Field::Zf;
                        else if(!field.isEmpty()) {
                            emit logLine("Invalid trace condition field.");
                            continue;
                        }
                        if(field=="ZF" && conditionValue>1) {
                            emit logLine("ZF condition must be 0 or 1.");
                            continue;
                        }
                        traceStop.equals=conditionValue;
                        traceRemaining=static_cast<quint32>(address);
                        traceThread=tid;
                        singleStepToPause=false;
                        stepThread=0;
                        emit logLine(QString("Bounded trace started: %1 instructions, TID %2")
                            .arg(traceRemaining).arg(tid));
                    } else {
                        singleStepToPause=stepping && performTrap;
                        stepThread=singleStepToPause?tid:0;
                    }
                    ready=true;
                    emit stateChanged("Running");
                }
            }
        }
        if(!ContinueDebugEvent(event.dwProcessId,event.dwThreadId,disposition)){
            emit logLine("ContinueDebugEvent: "+winError(GetLastError()));break;
        }
    }
    rearmIsolation.release();
    if(alive){
        // Any active breakpoint bytes must be restored before detaching.
        bool cleanRestore=true;
        for(const auto &[address,bp]:breakpoints) {
            if(bp.armed && !patchByte(pi.hProcess,address,bp.original)) {
                cleanRestore=false;
                emit logLine(QString("CRITICAL: unable to restore breakpoint 0x%1 before detach")
                             .arg(address,0,16));
            }
        }
        if(!cleanRestore) emit logLine("WARNING: debugger breakpoint bytes may remain in the target process.");
        if(!DebugActiveProcessStop(pi.dwProcessId))
            emit logLine("Detach failed: "+winError(GetLastError()));
        else emit logLine("Debugger detached; target keeps running.");
    }
    if(symbolsReady)SymCleanup(pi.hProcess);
    CloseHandle(pi.hProcess);
    emit stateChanged("Stopped");
#else
    Q_UNUSED(path);
    emit logLine("Windows Debugger requires a 64-bit Windows build.");
    emit stateChanged("Unavailable");
#endif
    running_=false;
}
