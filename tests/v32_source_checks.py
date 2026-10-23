from pathlib import Path
p=Path(__file__).resolve().parents[1]
cpp=(p/'src/WindowsDebugSession.cpp').read_text(encoding='utf8')
ui=(''.join((p/'src'/unit).read_text(encoding='utf8') for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
cmake=(p/'CMakeLists.txt').read_text(encoding='utf8')
checks={
'V3.2 project': 'VERSION 4.0' in cmake,
'bounded stop history': 'DebugTraceHistory stopHistory(512)' in cpp,
'signal integration': 'emit debugStopTraceChanged(rows)' in cpp,
'stop-view UI': 'DebuggerStopTrace' in ui,
'JSON includes trace': '"debugStopTrace",traceHistory->toPlainText()' in ui,
'actual C++ test': 'YASDebugTraceHistoryTests' in cmake,
'previous debugger controls': 'Command::Over' in cpp and 'Command::Into' in cpp,
'Windows workflow retained': (p/'.github/workflows/windows-build.yml').is_file(),
}
for name,ok in checks.items():print(('PASS' if ok else 'FAIL')+': '+name)
assert all(checks.values())
