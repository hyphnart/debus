from pathlib import Path
r=Path(__file__).resolve().parents[1]
h=(r/'src/WindowsDebugSession.h').read_text()
c=(r/'src/WindowsDebugSession.cpp').read_text()
u=(''.join((r/'src'/unit).read_text() for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
checks={'version':('VERSION 4.0' in (r/'CMakeLists.txt').read_text() or 'VERSION 4.0' in (r/'CMakeLists.txt').read_text()),
 'thread action':'Command::InspectThread' in c,
 'search bounded':'1024*1024' in c,
 'guard page check':'PAGE_GUARD' in c,
 'return candidates':'stackCandidates' in c,
 'thread input':'DebuggerCallStackCandidates' in u,
 'map filter':'mapFilter' in u,
 'Qt signals':'memorySearchResults' in h,
 'GitHub workflow':(r/'.github/workflows/windows-build.yml').exists()}
for key,result in checks.items():print(('PASS' if result else 'FAIL'),key)
assert all(checks.values())
