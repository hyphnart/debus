from pathlib import Path
root=Path(__file__).resolve().parents[1]
cmake=(root/'CMakeLists.txt').read_text()
main=(''.join((root/'src'/unit).read_text() for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
tasks=(root/'src/TaskRunner.h').read_text()
checks={
 'CMake version 3.7':'VERSION 4.0' in cmake,
 'Visual call graph':'VisualCallGraphDock' in main,
 'Graph function regions':'functionAnalysis.regions' in main,
 'Graph call edges':'callGraph.edges.append' in main,
 'Graph navigation':'visualCallView,&FlowGraphView::addressActivated' in main,
 'Task counter':'yas.activeTasks' in tasks,
 'Shutdown guard':'Background tasks running' in main,
 'Hash shutdown guard':'HashWorker' in main,
 'Existing CFG':'ControlFlowEngine::build(report)' in main,
 'Core C++ tests':(root/'tests/core_tests.cpp').exists(),
 'Function C++ tests':(root/'tests/function_tests.cpp').exists(),
 'Theme engine':(root/'src/AppTheme.cpp').exists() and 'appearance/dark' in main,
 'Compressed format':'YAS-SPLIT-2' in (root/'src/SplitEngine.cpp').read_text(),
 'Compression unit tests':'compressed roundtrip exact' in (root/'tests/core_tests.cpp').read_text(),
}
for key,value in checks.items():assert (root/"src/CrackmeInsights.cpp").exists()
assert "CrackmeInsights::scan(report)" in main
assert "YASCrackmeInsightsTests" in cmake
print(('PASS' if value else 'FAIL')+': '+key)
assert all(checks.values())

# Regression checks for the MSVC C2672 / Qt findChild failures seen in CI.
assert 'const int blockCount=static_cast<int>(snapshot.blocks.size())' in (root/'src/FlowGraphView.cpp').read_text()
assert 'findChild<QFutureWatcher<' not in main
assert 'findChildren<QObject*>("HashWorker")' in main
assert 'findChildren<QObject*>("AnalysisWorker")' in main
print('PASS: MSVC regression checks')

# Windows debugger module integration checks. Runtime requires GitHub Windows runner.
engine=(root/'src/WindowsDebugSession.cpp').read_text()
for label,passed in {
 'CreateProcessW integration': 'CreateProcessW(' in engine,
 'Debug event loop': 'WaitForDebugEvent(' in engine,
 'ContinueDebugEvent': 'ContinueDebugEvent(' in engine,
 'GetThreadContext (x64)': 'GetThreadContext(' in engine,
 'Detach': 'DebugActiveProcessStop(' in engine,
 'Exception pass-through': 'DBG_EXCEPTION_NOT_HANDLED' in engine,
 'Explicit execution approval': 'This operation EXECUTES the selected program' in main,
 'Qt debugger source': 'src/WindowsDebugSession.cpp' in cmake,
}.items():
 print(('PASS' if passed else 'FAIL')+': '+label)
 assert passed

# V2.1 debugger development checks
assert 'VERSION 4.0' in cmake
assert 'void WindowsDebugSession::stepInto()' in engine
assert 'void WindowsDebugSession::stepOver()' in engine
assert 'void WindowsDebugSession::toggleBreakpoint(' in engine
assert 'WriteProcessMemory(' in engine
assert 'ReadProcessMemory(' in engine
assert 'SetThreadContext(' in engine
assert 'stackChanged' in main
assert 'QKeySequence("F7")' in main and 'QKeySequence("F8")' in main
print('PASS: V2.1 step, breakpoint, stack wiring')

# V2.2 live debugging extension (static only; Windows runtime untested).
header=(root/'src/WindowsDebugSession.h').read_text()
assert 'void disassemblyChanged(' in header
assert 'void breakpointsChanged(' in header
assert 'ReadProcessMemory(process' in engine
assert 'decodeLive(pi.hProcess,ctx.Rip)' in engine
assert 'DebuggerLiveDisassembly' in main
assert 'DebuggerBreakpointList' in main
assert 'QTextCharFormat' in main
print('PASS: V2.2 live disassembly, breakpoints and register highlighting')
