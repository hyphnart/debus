from pathlib import Path
root=Path(__file__).resolve().parents[1]
checks={
 'v3 version':('VERSION 4.0' in (root/'CMakeLists.txt').read_text(encoding='utf-8') or 'VERSION 4.0' in (root/'CMakeLists.txt').read_text(encoding='utf-8')),
 'win integration test':'YASDebuggerIntegrationTests' in (root/'CMakeLists.txt').read_text(encoding='utf-8'),
 'regression test':'YASBreakpointStateTests' in (root/'CMakeLists.txt').read_text(encoding='utf-8'),
 'github test enable':'YAS_ENABLE_DEBUGGER_INTEGRATION=ON' in (root/'.github/workflows/windows-build.yml').read_text(encoding='utf-8'),
 'breakpoint restoration diagnostics':'CRITICAL: unable to restore breakpoint' in (root/'src/WindowsDebugSession.cpp').read_text(encoding='utf-8')}
for name,ok in checks.items():print(('PASS' if ok else 'FAIL')+': '+name)
assert all(checks.values())
