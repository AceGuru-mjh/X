cmake_minimum_required(VERSION 3.22.1)

project(unknown_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(UNKNOWN_NATIVE_BUILD_TESTS "Build the host-side unit tests (host builds only)" OFF)

# The portable matching core: no Android/JNI dependencies, testable on any host.
add_library(unknown_native_core OBJECT
    src/aho_corasick.cpp
    src/engine.cpp
    src/permission_index.cpp
    src/protocol.cpp
    src/regex_lite.cpp
    src/sha256.cpp
)
target_include_directories(unknown_native_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(NOT MSVC)
    target_compile_options(unknown_native_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# The Android shared library: matching core + JNI bridge. Only built when an
# Android toolchain (or explicit JNI headers) is available; host builds use
# the object library directly for tests.
if(ANDROID)
    add_library(unknown_native SHARED
        $<TARGET_OBJECTS:unknown_native_core>
        jni/native_engine_jni.cpp
    )
    target_include_directories(unknown_native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    if(NOT MSVC)
        # JNI entry points stay exported; everything else is hidden.
        target_compile_options(unknown_native PRIVATE -Wall -Wextra -Wpedantic -fvisibility=hidden)
    endif()
endif()

if(UNKNOWN_NATIVE_BUILD_TESTS AND NOT ANDROID)
    enable_testing()
    add_subdirectory(tests)
endif()
