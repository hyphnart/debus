from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(''.join((root/'src'/unit).read_text(encoding='utf-8') for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
engine=(root/'src/WindowsDebugSession.cpp').read_text(encoding='utf-8')
header=(root/'src/WindowsDebugSession.h').read_text(encoding='utf-8')
checks={
 'V2.4 CMake': ('VERSION 4.0' in (root/'CMakeLists.txt').read_text() or 'VERSION 4.0' in (root/'CMakeLists.txt').read_text()),
 'ReadMemory command': 'Command::ReadMemory' in engine and 'ReadMemory' in header,
 'Read request on debugger thread': 'memoryDumpChanged(memoryDump(pi.hProcess,address))' in engine,
 'Thread snapshots': 'CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0)' in engine,
 'Module snapshots': 'TH32CS_SNAPMODULE' in engine,
 'Snapshot handle cleanup': engine.count('CloseHandle(snapshot);')>=2,
 'Thread UI': 'DebuggerThreadExplorer' in main and 'threadListChanged,threads' in main,
 'Module UI': 'DebuggerModuleExplorer' in main and 'moduleListChanged,modules' in main,
 'Dump address UI': 'DebuggerMemoryAddress' in main and 'requestMemory(address)' in main,
 'Register history bounded': 'while(snapshots.size()>40)' in main,
 'Debugger confirmation': 'This operation EXECUTES the selected program' in main,
 'Github workflow': (root/'.github/workflows/windows-build.yml').exists(),
}
for name,ok in checks.items():print(('PASS' if ok else 'FAIL')+': '+name)
assert all(checks.values())
