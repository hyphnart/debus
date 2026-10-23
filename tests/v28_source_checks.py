from pathlib import Path
root=Path(__file__).resolve().parents[1]
source=(''.join((root/'src'/unit).read_text(encoding='utf-8') for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
cmake=(root/'CMakeLists.txt').read_text(encoding='utf-8')
checks={
 'version 2.8':('VERSION 4.0' in cmake or 'VERSION 4.0' in cmake),
 'five debugger tabs':all(x in source for x in ['CPU / Assembly','Memory / Map','Stack / Trace','Threads / Modules','Events / Snapshot']),
 'scrollable tabs':'new QScrollArea' in source,
 'snapshot export':'QSaveFile file(path)' in source,
 'snapshot schema':'yas-debug-snapshot-1' in source,
 'snapshot offline viewer':'Offline Debugger Snapshot' in source,
 'snapshot permission check':'Export debugging information' in source,
 'session safely stops':'if(debugSession_)debugSession_->stop();' in source,
 'debug core retained':(root/'src/WindowsDebugSession.cpp').exists(),
 'actions workflow retained':(root/'.github/workflows/windows-build.yml').exists()
}
for name,passed in checks.items():print(('PASS' if passed else 'FAIL')+': '+name)
assert all(checks.values())
