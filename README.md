# YAS BinaryLab X V4.0 — Maintainability Release

## Implemented

- Refactored the ~1,530-line `MainWindow.cpp` into **four translation units** without changing the UI or debug engine logic:
  - `MainWindow.cpp` — application construction, menu and action wiring.
  - `MainWindowFiles.cpp` — files, sessions, split/join, binary analysis, PE, diff, shutdown.
  - `MainWindowDisassembly.cpp` — Capstone disassembly, CFG, XREF, call graph, crackme insights.
  - `MainWindowDebugger.cpp` — Windows debugger dock and signals.
- Updated CMake source registration and window title.
- Added `tests/v40_architecture_checks.py`; retained existing source and C++ tests.
- Kept night/day theme, compressed splitting, breakpoint manager and GitHub Windows EXE workflow.

This is a **structural refactor**, not a new debugger engine. `MainWindow` still has too much responsibility; extracting full QWidget controllers is future work. In particular, no claim of fixing Windows breakpoint races is made.

## Windows build via GitHub
Push the extracted contents, including hidden `.github/workflows/windows-build.yml`, to repository root. Open Actions → Build YAS BinaryLab X Windows EXE and run the workflow. Check build logs and CTest before trusting the artifact.

## Local build
```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="C:/Qt/6.8.3/msvc2022_64" -DBUILD_TESTING=ON
cmake --build build --config Release --parallel 4
ctest --test-dir build -C Release --output-on-failure
python tests/v40_architecture_checks.py
```

## Verification boundaries
- Qt6/MSVC not installed in authoring container: real app compilation and UI runtime tests not performed.
- Architecture checks verify source registration and method ownership, **not** compiler correctness.
- GitHub Windows debugger smoke tests remain the gate for runtime behavior.
- Untrusted executables should only be run inside an isolated VM.
