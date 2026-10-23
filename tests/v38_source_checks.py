from pathlib import Path
r=Path(__file__).resolve().parents[1]
m=(''.join((r/'src'/unit).read_text(encoding='utf-8') for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
b=(r/'src/BreakpointManagerDialog.cpp').read_text(encoding='utf-8')
c=(r/'CMakeLists.txt').read_text(encoding='utf-8')
checks={
 'CMake V3.8 or newer':'VERSION 4.0' in c or 'VERSION 4.0' in c,
 'Dialog in executable':'src/BreakpointManagerDialog.cpp' in c,
 'Open manager command':'Debugger: Breakpoint Manager' in m,
 'Preset JSON import':'BreakpointPresetCodec::decode' in b,
 'Preset JSON export':'BreakpointPresetCodec::encode' in b,
 'Atomic export':'QSaveFile' in b,
 'Bounded input':'file.size()>1024*1024' in b,
 'Manual arming':'session_->toggleBreakpoint' in b,
 'Manual condition':'session_->configureBreakpointCondition' in b,
 'Existing test':'YASBreakpointPresetTests' in c,
}
for name,passed in checks.items():print(('PASS' if passed else 'FAIL')+': '+name)
assert all(checks.values())
