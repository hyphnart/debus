from pathlib import Path
root=Path(__file__).resolve().parents[1]
cmake=(root/'CMakeLists.txt').read_text(encoding='utf-8')
units={n:(root/'src'/n).read_text(encoding='utf-8') for n in
 ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')}
checks={
 'V4.0 in CMake':'VERSION 4.0' in cmake,
 'four compilation units':all(n in cmake for n in units),
 'constructor isolated':'MainWindow::MainWindow()' in units['MainWindow.cpp'],
 'file operations isolated':'MainWindow::splitFile()' in units['MainWindowFiles.cpp'],
 'disassembler isolated':'MainWindow::displayDisassembly(' in units['MainWindowDisassembly.cpp'],
 'debugger isolated':'MainWindow::startDebugSession()' in units['MainWindowDebugger.cpp'],
 'no duplicate definitions':all(sum(len(__import__('re').findall(r'(?m)^(?:void|bool|MainWindow::)\s*MainWindow::'+name+r'\s*\(', unit)) for unit in units.values())==1 for name in
    ['openFile','closeEvent','disassembleFile','startDebugSession']),
 'core test retained':(root/'tests/core_tests.cpp').is_file(),
 'debug integration retained':(root/'tests/debugger_integration.cpp').is_file(),
 'GitHub workflow retained':(root/'.github/workflows/windows-build.yml').is_file(),
}
for name,ok in checks.items(): print(('PASS' if ok else 'FAIL')+': '+name)
assert all(checks.values())
