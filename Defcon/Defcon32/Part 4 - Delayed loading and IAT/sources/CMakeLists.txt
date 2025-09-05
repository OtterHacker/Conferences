cmake_minimum_required(VERSION 3.27)
project(LoadLibrary C)

set(CMAKE_C_STANDARD 11)
set(SOURCES
        loadlibrary.c
        main.c
)
set(HEADERS
        loadlibrary.h
        peb.h
        msvc_api_definition.h
        winapi.h
)
add_executable(LoadLibrary ${SOURCES} ${HEADERS})
