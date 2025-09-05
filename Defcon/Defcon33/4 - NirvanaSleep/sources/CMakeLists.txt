cmake_minimum_required(VERSION 3.26)
project(NirvanaSleep C)

set(CMAKE_C_STANDARD 11)

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_definitions(MSVC=1)
else()
    add_compile_definitions(MSVC=0)
endif()


enable_language(ASM_NASM)
SET(ASM_OPTIONS "-x assembler-with-cpp")
SET(CMAKE_ASM_FLAGS "-masm=intel ${ASM_OPTIONS}" )

set(SOURCE
        ${SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/main.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/hook.asm
)

set(HEADERS
        ${HEADERS}
        ${CMAKE_CURRENT_SOURCE_DIR}/hook.h
        ${CMAKE_CURRENT_SOURCE_DIR}/common.h
        ${CMAKE_CURRENT_SOURCE_DIR}/utils.h
)

add_executable (NirvanaSleep ${SOURCE} ${HEADERS})
target_link_libraries(NirvanaSleep PUBLIC dbghelp dbghelp)
set_target_properties(NirvanaSleep PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)