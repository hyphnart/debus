cmake_minimum_required(VERSION 3.24)
project(YASBinaryLabX VERSION 4.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Widgets Concurrent)
qt_add_executable(YASBinaryLabX
    src/main.cpp
    src/MainWindow.h src/MainWindow.cpp
    src/MainWindowFiles.cpp src/MainWindowDisassembly.cpp src/MainWindowDebugger.cpp
    src/TaskRunner.h
    src/AppTheme.h src/AppTheme.cpp
    src/HexView.h src/HexView.cpp
    src/BinaryFile.h src/BinaryFile.cpp
    src/SplitEngine.h src/SplitEngine.cpp
    src/AnalysisEngine.h src/AnalysisEngine.cpp
    src/PEInspector.h src/PEInspector.cpp
    src/DiffEngine.h src/DiffEngine.cpp
    src/DisassemblyEngine.h src/DisassemblyEngine.cpp
    src/ControlFlowEngine.h src/ControlFlowEngine.cpp
    src/FlowGraphView.h src/FlowGraphView.cpp
    src/CrossReferenceEngine.h src/CrossReferenceEngine.cpp
    src/FunctionAnalysisEngine.h src/FunctionAnalysisEngine.cpp
    src/CrackmeInsights.h src/CrackmeInsights.cpp
    src/WindowsDebugSession.h src/WindowsDebugSession.cpp
    src/DebugTraceHistory.h
    src/TraceStopCondition.h
    src/ConditionalBreakpointPolicy.h
    src/BreakpointDecision.h
    src/BreakpointPreset.h src/BreakpointPreset.cpp
    src/BreakpointManagerDialog.h src/BreakpointManagerDialog.cpp
)
target_link_libraries(YASBinaryLabX PRIVATE Qt6::Core Qt6::Widgets Qt6::Concurrent)
set_target_properties(YASBinaryLabX PROPERTIES WIN32_EXECUTABLE TRUE)
if(WIN32)
    target_link_libraries(YASBinaryLabX PRIVATE dbghelp)
    # Required by the debug event thread's DbgHelp-based symbol stack walker.
endif()

# Optional Capstone disassembler: the application still builds without it.
find_path(CAPSTONE_INCLUDE_DIR NAMES capstone/capstone.h)
find_library(CAPSTONE_LIBRARY NAMES capstone)
if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
    target_include_directories(YASBinaryLabX PRIVATE "${CAPSTONE_INCLUDE_DIR}")
    target_link_libraries(YASBinaryLabX PRIVATE "${CAPSTONE_LIBRARY}")
    target_compile_definitions(YASBinaryLabX PRIVATE YAS_HAS_CAPSTONE=1)
    message(STATUS "Capstone enabled")
else()
    message(STATUS "Capstone not found: disassembly action will explain installation")
endif()


include(CTest)
if(BUILD_TESTING)
    add_executable(YASCoreTests
        tests/core_tests.cpp
        src/SplitEngine.h src/SplitEngine.cpp
        src/DiffEngine.h src/DiffEngine.cpp
    )
    target_include_directories(YASCoreTests PRIVATE src)
    target_link_libraries(YASCoreTests PRIVATE Qt6::Core)
    add_test(NAME YASCoreTests COMMAND YASCoreTests)
endif()

if(BUILD_TESTING)
    add_executable(YASXrefTests tests/xref_tests.cpp src/CrossReferenceEngine.h src/CrossReferenceEngine.cpp
    src/FunctionAnalysisEngine.h src/FunctionAnalysisEngine.cpp)
    target_include_directories(YASXrefTests PRIVATE src)
    target_link_libraries(YASXrefTests PRIVATE Qt6::Core)
    add_test(NAME YASXrefTests COMMAND YASXrefTests)
endif()

if(BUILD_TESTING)
    add_executable(YASFunctionTests tests/function_tests.cpp
        src/FunctionAnalysisEngine.h src/FunctionAnalysisEngine.cpp
        src/CrossReferenceEngine.h src/CrossReferenceEngine.cpp)
    target_include_directories(YASFunctionTests PRIVATE src)
    target_link_libraries(YASFunctionTests PRIVATE Qt6::Core)
    add_test(NAME YASFunctionTests COMMAND YASFunctionTests)
endif()

if(BUILD_TESTING)
    add_executable(YASCrackmeInsightsTests tests/crackme_insights_tests.cpp
        src/CrackmeInsights.h src/CrackmeInsights.cpp
    src/WindowsDebugSession.h src/WindowsDebugSession.cpp
    src/DebugTraceHistory.h)
    target_include_directories(YASCrackmeInsightsTests PRIVATE src)
    target_link_libraries(YASCrackmeInsightsTests PRIVATE Qt6::Core)
    add_test(NAME YASCrackmeInsightsTests COMMAND YASCrackmeInsightsTests)
endif()


# DbgHelp symbols are referenced by WindowsDebugSession.cpp in the test target too.
if(WIN32 AND BUILD_TESTING)
    target_link_libraries(YASCrackmeInsightsTests PRIVATE dbghelp)
endif()

# Headless, platform-independent breakpoint bookkeeping tests.
if(BUILD_TESTING)
    add_executable(YASBreakpointStateTests tests/breakpoint_state_tests.cpp src/BreakpointState.h)
    target_include_directories(YASBreakpointStateTests PRIVATE src)
    add_test(NAME YASBreakpointStateTests COMMAND YASBreakpointStateTests)
endif()

# Real Win64 smoke test uses an intentionally harmless child process.
# Opt-in: debugger integration tests depend on the runner's debug rights.
option(YAS_ENABLE_DEBUGGER_INTEGRATION "Run Win64 debug-event smoke test" OFF)
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND BUILD_TESTING AND YAS_ENABLE_DEBUGGER_INTEGRATION)
    add_executable(YASDebugTarget tests/debug_target.cpp)
    add_executable(YASDebuggerIntegrationTests tests/debugger_integration.cpp
        src/WindowsDebugSession.cpp src/WindowsDebugSession.h)
    target_include_directories(YASDebuggerIntegrationTests PRIVATE src)
    target_link_libraries(YASDebuggerIntegrationTests PRIVATE Qt6::Core dbghelp)
    add_test(NAME YASDebuggerIntegrationTests COMMAND YASDebuggerIntegrationTests $<TARGET_FILE:YASDebugTarget>)
    set_tests_properties(YASDebuggerIntegrationTests PROPERTIES TIMEOUT 20)
endif()

# Platform-independent, real C++ behavioral test for bounded trace storage.
if(BUILD_TESTING)
    add_executable(YASDebugTraceHistoryTests tests/debug_trace_history_tests.cpp src/DebugTraceHistory.h)
    target_include_directories(YASDebugTraceHistoryTests PRIVATE src)
    add_test(NAME YASDebugTraceHistoryTests COMMAND YASDebugTraceHistoryTests)
endif()

if(BUILD_TESTING)
    add_executable(YASTraceConditionTests tests/trace_condition_tests.cpp src/TraceStopCondition.h src/DebugTraceHistory.h)
    target_include_directories(YASTraceConditionTests PRIVATE src)
    add_test(NAME YASTraceConditionTests COMMAND YASTraceConditionTests)
endif()

if(BUILD_TESTING)
    add_executable(YASConditionalBreakpointPolicyTests tests/conditional_breakpoint_policy_tests.cpp src/ConditionalBreakpointPolicy.h)
    target_include_directories(YASConditionalBreakpointPolicyTests PRIVATE src)
    add_test(NAME YASConditionalBreakpointPolicyTests COMMAND YASConditionalBreakpointPolicyTests)
endif()

if(BUILD_TESTING)
    add_executable(YASBreakpointPresetTests tests/breakpoint_preset_tests.cpp src/BreakpointPreset.cpp src/BreakpointPreset.h)
    target_include_directories(YASBreakpointPresetTests PRIVATE src)
    target_link_libraries(YASBreakpointPresetTests PRIVATE Qt6::Core)
    add_test(NAME YASBreakpointPresetTests COMMAND YASBreakpointPresetTests)
endif()

if(BUILD_TESTING)
    add_executable(YASBreakpointDecisionTests tests/breakpoint_decision_tests.cpp src/BreakpointDecision.h)
    target_include_directories(YASBreakpointDecisionTests PRIVATE src)
    target_link_libraries(YASBreakpointDecisionTests PRIVATE Qt6::Core)
    add_test(NAME YASBreakpointDecisionTests COMMAND YASBreakpointDecisionTests)
endif()
