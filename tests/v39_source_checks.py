from pathlib import Path
r=Path(__file__).resolve().parents[1]
c=(r/'CMakeLists.txt').read_text()
s=(r/'src/WindowsDebugSession.cpp').read_text()
d=(r/'src/BreakpointDecision.h').read_text()
checks={
    'V4.0 project':'VERSION 4.0' in c,
    'pure decision API':'evaluateBreakpoint(' in d,
    'thread-only filter':'rule.field=TraceStopCondition::Field::None;' in s,
    'dedicated statistics':'stats.record(decision)' in s,
    'actual auto-continue count':'++stats.automaticContinues' in s,
    'decision regression tests':'YASBreakpointDecisionTests' in c,
}
for k,v in checks.items():print(('PASS' if v else 'FAIL')+': '+k)
assert all(checks.values())
