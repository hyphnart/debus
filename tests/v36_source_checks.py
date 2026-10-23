from pathlib import Path
r=Path(__file__).resolve().parents[1]
s=(r/'src/WindowsDebugSession.cpp').read_text()
u=(''.join((r/'src'/unit).read_text() for unit in ('MainWindow.cpp','MainWindowFiles.cpp','MainWindowDisassembly.cpp','MainWindowDebugger.cpp')))
assert 'ConditionalBreakpointPolicy' in s
assert 'rearmIsolation.acquire(pi.dwProcessId,tid)' in s
assert 'condition false' in s.lower()
assert 'Auto-continue when condition is false' in u
assert (r/'tests/conditional_breakpoint_policy_tests.cpp').exists()
print('PASS: v3.6 conditional breakpoint integration static checks')
