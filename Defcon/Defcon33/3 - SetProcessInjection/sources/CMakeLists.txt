cmake_minimum_required(VERSION 3.27)
project(SetProcessInjection C)

set(CMAKE_C_STANDARD 11)

enable_language(ASM_NASM)
SET(ASM_OPTIONS "-x assembler-with-cpp")
SET(CMAKE_ASM_FLAGS "-masm=intel ${ASM_OPTIONS}" )

set(SOURCE
        ${SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/aes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers.c
        ${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

set(HEADERS
        ${HEADERS}
        ${CMAKE_CURRENT_SOURCE_DIR}/aes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sc.h
)

add_executable(SetProcessInjection ${SOURCE} ${HEADERS})
