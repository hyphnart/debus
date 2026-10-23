from pathlib import Path
r=Path(__file__).resolve().parents[1]
s=(r/'src/WindowsDebugSession.cpp').read_text(encoding='utf-8')
u=(''.join((r/'src'/unit).read_text(encoding='utf-8') for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
c=(r/'CMakeLists.txt').read_text(encoding='utf-8')
checks={
 'version 3.4':'VERSION 4.0' in c,
 'trace predicate header':(r/'src/TraceStopCondition.h').exists(),
 'predicate used in worker':'traceStop.matches(record)' in s,
 'bounded trace preserved':'address>1000' in s,
 'UI condition field':'DebuggerTraceStopField' in u,
 'trace navigation':'DebuggerTraceNavigate' in u,
 'condition test in CMake':'YASTraceConditionTests' in c,
 'windows workflow':(r/'.github/workflows/windows-build.yml').exists(),
}
for k,v in checks.items(): print(('PASS' if v else 'FAIL')+': '+k)
assert all(checks.values())
