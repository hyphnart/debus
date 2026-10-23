# x64dbg technical research and BinaryLab roadmap

References:
- Official x64dbg repository: https://github.com/x64dbg/x64dbg
- Features: https://github.com/x64dbg/x64dbg/blob/development/docs/introduction/Feature-set.md
- Conditional breakpoints: https://help.x64dbg.com/en/latest/introduction/ConditionalBreakpoint.html
- Conditional tracing: https://help.x64dbg.com/en/latest/introduction/ConditionalTracing.html
- License: https://github.com/x64dbg/x64dbg/blob/development/LICENSE (modified GPLv3)

x64dbg has a Windows user-mode debugger core (TitanEngine), instruction disassembly, registers, stack, memory map, conditional breakpoints, tracing, PDB symbols, patching and plugins. BinaryLab X presently has **static** PE parsing, read-only hex view, disassembly (only if optional Capstone is found), basic graphs, strings, XREFs and split/join. No executable debugger is embedded. Avoid presenting static analysis as execution stepping or verified crackme solving.

License boundary: this package uses original code and has not copied, embedded or linked x64dbg code. Integrating x64dbg source would require evaluating its GPLv3-derived licensing terms and component dependencies.

Planned phases:
1. **V1.9 shipped**: learning/CTF clue engine for directly decoded compare + conditional-jump pairs and immediate CALL references, with navigable Qt panel and deterministic unit tests.
2. Windows debug abstraction (attach/start, pause/continue, stop, architecture-aware thread contexts); isolate inferior process and guard against unintended executable execution.
3. Software breakpoints, step in/over, register & flag inspector, memory map, stack and threads; safeguards for breakpoint cleanup.
4. Conditional breakpoints and trace recording, persistence of comments/labels, PDB symbols, disassembly highlighting; graph-linked replay.
5. Test with independently authored harmless sample crackmes on both x86/x64 and run real GitHub MSVC tests.

Ethical scope: analyze binaries you own or have permission to test. No tools for covert persistence or credential theft are implemented.
