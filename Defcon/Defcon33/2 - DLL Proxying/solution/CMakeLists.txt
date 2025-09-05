cmake_minimum_required(VERSION 3.27)
project(SyscallHijackDll C)

set(CMAKE_C_STANDARD 11)

enable_language(ASM_NASM)
SET(ASM_OPTIONS "-x assembler-with-cpp")
SET(CMAKE_ASM_FLAGS "-masm=intel ${ASM_OPTIONS}" )

set(SOURCE
        ${SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/hook.asm
        ${CMAKE_CURRENT_SOURCE_DIR}/dllmain.c
)

set(HEADERS
        ${HEADERS}
        ${CMAKE_CURRENT_SOURCE_DIR}/main.h
)

add_library(libcrypto SHARED ${SOURCE} ${HEADERS})
