cmake_minimum_required(VERSION 3.27)
project(LoadLibrary C)

set(CMAKE_C_STANDARD 11)
set(SOURCES
        loadlibrary.c
        winapi.c
        main.c
)
set(HEADERS
        loadlibrary.h
        msvc_api_definition.h
        peb.h
        utils.h
        winapi.h
)
add_executable(LoadLibrary ${SOURCES} ${HEADERS})
