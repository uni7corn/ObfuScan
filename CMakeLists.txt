cmake_minimum_required(VERSION 3.15)
project(ObfuScan LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
        capstone
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        GIT_TAG 5.0.6
)

# 只做静态库，避免 DLL 依赖问题
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
foreach(CAPSTONE_ARCH ARM X86 M68K MIPS PPC SPARC SYSZ XCORE TMS320C64X
                      M680X EVM MOS65XX WASM BPF RISCV SH TRICORE)
    set(CAPSTONE_${CAPSTONE_ARCH}_SUPPORT OFF CACHE BOOL "" FORCE)
endforeach()
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(capstone)

# 如果使用的是 MinGW 编译器，开启静态链接，把运行库打包进 exe
if(MINGW)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

add_library(obfuscan_core STATIC
        apk_scan_limits.cpp
        apk_scan_limits.h
        custom_linker_detector.cpp
        custom_linker_detector.h
        disasm_arm64.cpp
        disasm_arm64.h
        elf_dynamic.cpp
        elf_dynamic.h
        vmp_detector.cpp
        vmp_detector.h
        vmp_linkage.cpp
        vmp_linkage.h
)

target_include_directories(obfuscan_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(obfuscan_core PUBLIC capstone)

add_executable(ObfuScan
        main.cpp
        miniz.c
)

target_link_libraries(ObfuScan PRIVATE obfuscan_core)
if(WIN32)
    target_link_libraries(ObfuScan PRIVATE shell32)
endif()

if (MSVC)
    target_compile_options(obfuscan_core PRIVATE /W4 /EHsc /utf-8)
    target_compile_options(ObfuScan PRIVATE /W4 /EHsc /utf-8)
else()
    target_compile_options(obfuscan_core PRIVATE -Wall -Wextra -Wpedantic -O2)
    target_compile_options(ObfuScan PRIVATE -Wall -Wextra -Wpedantic -O2)
endif()

include(CTest)
if (BUILD_TESTING)
    add_executable(vmp_detector_tests
            tests/vmp_detector_tests.cpp
    )
    target_link_libraries(vmp_detector_tests PRIVATE obfuscan_core)
    if (MSVC)
        target_compile_options(vmp_detector_tests PRIVATE /W4 /EHsc /utf-8)
    else()
        target_compile_options(vmp_detector_tests PRIVATE -Wall -Wextra -Wpedantic -O2)
    endif()
    add_test(NAME vmp_detector_tests COMMAND vmp_detector_tests)

    add_executable(elf_dynamic_tests
            tests/elf_dynamic_tests.cpp
    )
    target_link_libraries(elf_dynamic_tests PRIVATE obfuscan_core)
    if (MSVC)
        target_compile_options(elf_dynamic_tests PRIVATE /W4 /EHsc /utf-8)
    else()
        target_compile_options(elf_dynamic_tests PRIVATE -Wall -Wextra -Wpedantic -O2)
    endif()
    add_test(NAME elf_dynamic_tests COMMAND elf_dynamic_tests)

    add_executable(vmp_linkage_tests
            tests/vmp_linkage_tests.cpp
    )
    target_link_libraries(vmp_linkage_tests PRIVATE obfuscan_core)
    if (MSVC)
        target_compile_options(vmp_linkage_tests PRIVATE /W4 /EHsc /utf-8)
    else()
        target_compile_options(vmp_linkage_tests PRIVATE -Wall -Wextra -Wpedantic -O2)
    endif()
    add_test(NAME vmp_linkage_tests COMMAND vmp_linkage_tests)

    add_executable(apk_scan_limits_tests
            tests/apk_scan_limits_tests.cpp
    )
    target_link_libraries(apk_scan_limits_tests PRIVATE obfuscan_core)
    if (MSVC)
        target_compile_options(apk_scan_limits_tests PRIVATE /W4 /EHsc /utf-8)
    else()
        target_compile_options(apk_scan_limits_tests PRIVATE -Wall -Wextra -Wpedantic -O2)
    endif()
    add_test(NAME apk_scan_limits_tests COMMAND apk_scan_limits_tests)

    add_executable(custom_linker_detector_tests
            tests/custom_linker_detector_tests.cpp
    )
    target_link_libraries(custom_linker_detector_tests PRIVATE obfuscan_core)
    if (MSVC)
        target_compile_options(custom_linker_detector_tests PRIVATE /W4 /EHsc /utf-8)
    else()
        target_compile_options(custom_linker_detector_tests PRIVATE -Wall -Wextra -Wpedantic -O2)
    endif()
    add_test(NAME custom_linker_detector_tests COMMAND custom_linker_detector_tests)

    find_package(Python3 COMPONENTS Interpreter QUIET)
    if (Python3_Interpreter_FOUND)
        add_test(
                NAME resource_limit_regression
                COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/tests/resource_limit_regression.py
                        $<TARGET_FILE:ObfuScan>
        )
        set_tests_properties(resource_limit_regression PROPERTIES TIMEOUT 60)
    endif()
endif()
