from pathlib import Path
root=Path(__file__).resolve().parents[1]
src=(root/'src/WindowsDebugSession.cpp').read_text(encoding='utf-8')
ui=(''.join((root/'src'/unit).read_text(encoding='utf-8') for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
cm=(root/'CMakeLists.txt').read_text(encoding='utf-8')
checks={'version':'VERSION 4.0' in cm,'breakpoint command':'Command::ConfigureBreakpoint' in src,'condition matching':'evaluateBreakpoint(' in src,'safe pause':'stopping instead of auto-continue' in src,'condition UI':'Set Breakpoint Condition' in ui,'clear condition':'breakpointConditions.erase(address)' in src,'previous trace':'traceRemaining' in src}
for name,ok in checks.items():print(('PASS' if ok else 'FAIL')+': '+name)
assert all(checks.values())
