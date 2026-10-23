from pathlib import Path
root=Path(__file__).resolve().parents[1]
core=(root/'src/WindowsDebugSession.cpp').read_text()
ui=(''.join((root/'src'/unit).read_text() for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
h=(root/'src/WindowsDebugSession.h').read_text()
cmake=(root/'CMakeLists.txt').read_text()
checks={
 'V3.3 CMake version':'VERSION 4.0' in cmake,
 'bounded trace command':'void traceInstructions(quint32 count)' in h,
 'max 1000 steps':'address>1000' in core,
 'trace event handling':'const bool traceStep=' in core,
 'trace thread ownership':'traceThread==tid' in core,
 'trace sample storage':'record.cause="instruction-trace"' in core,
 'trace refuses pending breakpoint rearm':'Trace refused while' in core,
 'trace UI':'DebuggerTraceInstructions' in ui,
 'trace filtering':'DebuggerTraceFilter' in ui,
 'existing stop export':'"debugStopTrace",traceHistory->toPlainText()' in ui,
 'GitHub Actions':(root/'.github/workflows/windows-build.yml').exists()
}
for name,good in checks.items():print(('PASS' if good else 'FAIL')+': '+name)
assert all(checks.values())
