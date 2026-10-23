from pathlib import Path
r=Path(__file__).resolve().parents[1]
h=(r/'src/WindowsDebugSession.h').read_text()
c=(r/'src/WindowsDebugSession.cpp').read_text()
u=(''.join((r/'src'/unit).read_text() for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
cm=(r/'CMakeLists.txt').read_text()
checks={
    'version':'VERSION 4.0' in cm,
    'thread filter API':'pendingConditionThread_' in h,
    'thread-match check':'evaluateBreakpoint(' in c,
    'thread mismatch log':'Breakpoint thread filter mismatch.' in c,
    'thread filter input':'Thread ID decimal (0 = any thread)' in u,
    'preset codec':(r/'src/BreakpointPreset.cpp').exists(),
    'preset test target':'YASBreakpointPresetTests' in cm,
    'minimum CMake compatibility':'cmake_minimum_required(VERSION 3.24)' in cm,
}
for key,valid in checks.items(): print(('PASS' if valid else 'FAIL')+': '+key)
assert all(checks.values())
