set(UNKNOWN_NATIVE_TEST_NAMES
    test_aho_corasick
    test_engine
    test_permission_index
    test_protocol
    test_regex_lite
    test_sha256
)

foreach(test_name IN LISTS UNKNOWN_NATIVE_TEST_NAMES)
    add_executable(${test_name} ${test_name}.cpp)
    target_link_libraries(${test_name} PRIVATE unknown_native_core)
    if(NOT MSVC)
        target_compile_options(${test_name} PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
