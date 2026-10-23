from pathlib import Path
r=Path(__file__).resolve().parents[1]
s=(r/'src/WindowsDebugSession.cpp').read_text(encoding='utf-8')
main=(''.join((r/'src'/unit).read_text(encoding='utf-8') for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
cmake=(r/'CMakeLists.txt').read_text(encoding='utf-8')
checks={
'2.9 package version':('VERSION 4.0' in cmake or ('VERSION 4.0' in cmake or 'VERSION 4.0' in cmake)),
'2.9 app title':'YAS BinaryLab X — V4.0' in main,
'step thread ownership':'stepThread==tid' in s,
'maintenance single step ownership':'maintenanceStep=(rearmAddress!=0 && rearmThread==tid)' in s,
'breakpoint rearm error':'breakpoint rearm failed' in s,
'breakpoint removal error':'Failed to remove breakpoint' in s,
'register read failure handling':'resume aborted' in s,
'unexpected steps forwarded':'disposition=DBG_EXCEPTION_NOT_HANDLED' in s,
'Qt Windows debugger source present':(r/'src/WindowsDebugSession.h').is_file(),
'GitHub CI maintained':(r/'.github/workflows/windows-build.yml').is_file(),
}
for name,ok in checks.items():print(('PASS' if ok else 'FAIL')+': '+name)
assert all(checks.values())
