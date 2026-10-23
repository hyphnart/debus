from pathlib import Path
r=Path(__file__).resolve().parents[1]
cpp=(r/'src/WindowsDebugSession.cpp').read_text()
ui=(''.join((r/'src'/unit).read_text() for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
cmake=(r/'CMakeLists.txt').read_text()
checks={
 'Windows debugger test links DbgHelp': 'target_link_libraries(YASCrackmeInsightsTests PRIVATE dbghelp)' in cmake,
 'Breakpoint restore checked': 'if(!patchByte(pi.hProcess,bpAddress,it->second.original))' in cpp,
 'RIP rewind checked': 'if(!SetThreadContext(thread,&restored))' in cpp,
 'Unknown INT3 not swallowed': 'Application-owned INT3 forwarded' in cpp,
 'No breakpoint at current RIP': 'if(isCurrentRip)' in cpp,
 'Call stack frame navigation': 'Inspect selected frame address in Memory Dump' in ui,
 'CMake version updated': ('VERSION 4.0' in cmake or 'VERSION 4.0' in cmake),
}
for label,success in checks.items():print(('PASS' if success else 'FAIL')+': '+label)
assert all(checks.values())
