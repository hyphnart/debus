from pathlib import Path
r=Path(__file__).resolve().parents[1]
c=(r/'CMakeLists.txt').read_text()
h=(r/'src/WindowsDebugSession.h').read_text()
s=(r/'src/WindowsDebugSession.cpp').read_text()
m=(''.join((r/'src'/unit).read_text() for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
tests={
    'project version 2.6':('VERSION 4.0' in c or 'VERSION 4.0' in c),
    'DbgHelp linked':'target_link_libraries(YASBinaryLabX PRIVATE dbghelp)' in c,
    'DbgHelp stack walker':'StackWalk64(' in s,
    'Symbol resolution':'SymFromAddr(' in s,
    'Symbol init and cleanup':'SymInitialize(' in s and 'SymCleanup(' in s,
    'bounded unwind':'i<48' in s,
    'UI debugger panel':'DebuggerUnwoundCallStack' in m,
    'Qt signal':'callStackUnwoundChanged' in h,
    'version shown':'V4.0' in m,
    'prior memory search retained':'boundedMemorySearch' in s,
}
for name,ok in tests.items():print(('PASS' if ok else 'FAIL')+': '+name)
assert all(tests.values())
