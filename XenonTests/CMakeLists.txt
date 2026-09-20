project("XenonTests")

file(GLOB TEST_FILES *.cpp)

if(TEST_FILES)
    add_executable(XenonTests 
        ${TEST_FILES}
    )
    target_link_libraries(XenonTests 
        PUBLIC 
            XenonUtils
            fmt::fmt
    )
    target_compile_options(XenonTests
        PRIVATE 
            "-march=sandybridge"
            "-Wno-unused-label"
            "-Wno-unused-variable"
    )
endif()

find_package(Python3 COMPONENTS Interpreter)
if(BUILD_TESTING AND Python3_Interpreter_FOUND)
    add_test(
        NAME xenon_dcbz_codegen_contract
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/test_dcbz_codegen.py
                ${XENONRECOMP_ROOT}/recompiler.cpp)
    add_test(
        NAME xenon_rotate_record_codegen_contract
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/test_rotate_record_codegen.py
                ${XENONRECOMP_ROOT}/recompiler.cpp)
endif()
