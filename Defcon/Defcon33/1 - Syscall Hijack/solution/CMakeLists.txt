cmake_minimum_required(VERSION 3.27)
project(SyscallHijack C)

set(CMAKE_C_STANDARD 11)

enable_language(ASM_NASM)
SET(ASM_OPTIONS "-x assembler-with-cpp")
SET(CMAKE_ASM_FLAGS "-masm=intel ${ASM_OPTIONS}" )

set(SOURCE
        ${SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/hook.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

set(HEADERS
        ${HEADERS}
)

add_executable(SyscallHijack ${SOURCE} ${HEADERS})
