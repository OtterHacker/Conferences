#ifndef AZRAEL_IMPLANT_WIN_API_H
#define AZRAEL_IMPLANT_WIN_API_H

#include "msvc_api_definition.h"

#define DEBUG_LEVEL 2
#if DEBUG_LEVEL == 1
#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)
    #define DEBUG_MEDIUM(x, ...)
    #define DEBUG_LOW(x, ...)
    #define DEBUG_NATIVE(x, ...)
#elif DEBUG_LEVEL == 2
#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#define DEBUG_MEDIUM(x, ...) printf(x, ##__VA_ARGS__)
#define DEBUG_LOW(x, ...)
#define DEBUG_NATIVE(x, ...)
#elif DEBUG_LEVEL == 3
#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)
    #define DEBUG_MEDIUM(x, ...) printf(x, ##__VA_ARGS__)
    #define DEBUG_LOW(x, ...) printf(x, ##__VA_ARGS__)
    #define DEBUG_NATIVE(x, ...)
#elif DEBUG_LEVEL == 4
    #define DEBUG(x, ...) printf(x, ##__VA_ARGS__)
    #define DEBUG_MEDIUM(x, ...) printf(x, ##__VA_ARGS__)
    #define DEBUG_LOW(x, ...) printf(x, ##__VA_ARGS__)
    #define DEBUG_NATIVE(x, ...) printf(x, ##__VA_ARGS__)
#else
    #define DEBUG(x, ...)
    #define DEBUG_MEDIUM(x, ...)
    #define DEBUG_LOW(x, ...)
    #define DEBUG_NATIVE(x, ...)
#endif

typedef unsigned __int64    QWORD;

#define SECTION_SIZE 0x28

typedef struct _PERelocation {
    DWORD RVA;
    WORD Type : 4;
} PERelocation;

typedef struct _IMAGE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

typedef struct _PE {
    BOOL memoryMapped;
    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS* ntHeader;
    IMAGE_OPTIONAL_HEADER* optionalHeader;
    IMAGE_DATA_DIRECTORY* dataDirectory;
    IMAGE_EXPORT_DIRECTORY* exportDirectory;
    IMAGE_SECTION_HEADER* sectionHeader;
    LPDWORD AddressOfFunctions;
    LPDWORD AddressOfNames;
    LPWORD AddressOfNameOrdinals;
    DWORD NumberOfNames;
    PERelocation* relocations;
    DWORD numberOfRelocations;
    PVOID baseAddress;
} PE;

typedef struct __ILT_ENTRY_64 {
    union {
        DWORD ORDINAL : 16;
        DWORD HINT_NAME_TABE : 32;
    } FIELD_2;
    DWORD ORDINAL_NAME_FLAG : 1;
} ILT_ENTRY_64, * PILT_ENTRY_64;

typedef BOOL(WINAPI* LPDLLMAIN)(DWORD_PTR image_base, DWORD reason, LPVOID reserved);


#define WIN32_FUNC( x ) MSVC$##x x
#define NT_FUNC( x ) MSVC$##x x
#define WIN32_DECL( x ) MSVC$##x win32_##x
#define NT_DECL( x ) MSVC$##x win32_##x

#if SHELLCODE
#define  __attribute__( ( section( "." #s "$" #x "" ) ) )
    #define GET_SYMBOL( x )     ( ULONG_PTR )( GetRIP() - ( ( ULONG_PTR ) & GetRIP - ( ULONG_PTR ) x ) )
    unsigned long long GetRIP( void );
#else
#define SEC( s, x )
#define GET_SYMBOL( x )     x
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <WS2tcpip.h>
#include <winhttp.h>

#endif //AZRAEL_IMPLANT_WIN_API_H