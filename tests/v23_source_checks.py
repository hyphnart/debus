from pathlib import Path
r=Path(__file__).resolve().parents[1]
a=(r/'src/WindowsDebugSession.cpp').read_text()
b=(''.join((r/'src'/unit).read_text() for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
h=(r/'src/WindowsDebugSession.h').read_text()
checks={
 'VirtualQueryEx used': 'VirtualQueryEx(' in a,
 'ReadProcessMemory used': 'ReadProcessMemory(' in a,
 'EFLAGS parsed': 'cpuFlags(ctx.EFlags)' in a,
 'Memory map UI wired': 'memoryMapChanged,map' in b,
 'Dump UI wired': 'memoryDumpChanged,dump' in b,
 'Flag UI wired': 'cpuFlagsChanged,flags' in b,
 'Signals declared': all(x in h for x in ['memoryMapChanged','memoryDumpChanged','cpuFlagsChanged']),
 'Read-only dump': 'dump->setReadOnly(true)' in b,
 'Bounded enumeration': 'shown<256' in a,
 'CMake Version': ('VERSION 4.0' in (r/'CMakeLists.txt').read_text() or 'VERSION 4.0' in (r/'CMakeLists.txt').read_text()),
 'CI workflow retained': (r/'.github/workflows/windows-build.yml').is_file(),
}
for k,v in checks.items():print(('PASS' if v else 'FAIL')+': '+k)
assert all(checks.values())
