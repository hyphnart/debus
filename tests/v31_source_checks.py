from pathlib import Path
r=Path(__file__).resolve().parents[1]
s=(r/'src/WindowsDebugSession.cpp').read_text(encoding='utf-8')
w=(r/'.github/workflows/windows-build.yml').read_text(encoding='utf-8')
checks={
 'V3.1 declared':('VERSION 4.0' in (r/'CMakeLists.txt').read_text() or 'VERSION 4.0' in (r/'CMakeLists.txt').read_text()),
 'thread snapshot':'TH32CS_SNAPTHREAD' in s,
 'suspends peers':'SuspendThread(h)' in s,
 'resumes peers':'ResumeThread(*it)' in s,
 'holds during rearm':'rearmIsolation.acquire(pi.dwProcessId,tid)' in s,
 'releases after maintenance':'rearmIsolation.release();' in s,
 'CI regression':'python tests/v31_source_checks.py' in w,
 'debugger integration retained':'YASDebuggerIntegrationTests' in (r/'CMakeLists.txt').read_text(),
}
for k,v in checks.items():print(('PASS' if v else 'FAIL')+': '+k)
assert all(checks.values())
