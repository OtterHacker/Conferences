#ifndef AZRAEL_IMPLANT_LOADLIBRARY_H
#define AZRAEL_IMPLANT_LOADLIBRARY_H
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#define DEBUG_LEVEL 1

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

PBYTE read_file_w(LPWSTR filename, PDWORD file_size);

/*
 * Helper that given a base address will map the element
 * in a structure representing the PE.
 */
PE *pe_create(PVOID image_base, BOOL is_memory_mapped);
PVOID resolve_rva(PE* pe, DWORD64 rva);

/*
 * Read the DLL file to load and map the section in memory
 */
PVOID minimal_memory_map(LPWSTR filepath);

/*
 * Process the memory mapped DLL relocations
 */
BOOL rebase(PE *dll_parsed);

/*
 * Resolve dependencies and fill the DLL IAT
 */
BOOL snapping(PE *dll_parsed);

/*
 * Set the protection on the DLL sections and run the entrypoint
 */
BOOL run_entrypoint(PE *dll_parsed);


PVOID load_library_ex_a(LPCSTR dllName, HANDLE file, DWORD dwFlags);
PVOID load_library_ex_w(LPWSTR dllName, HANDLE file, DWORD dwFlags);
PVOID load_library_w(LPWSTR filepath);
PVOID load_library_a(LPSTR filepath);
PVOID ldr_load_dll(LPWSTR filepath, HANDLE file, DWORD dwFlags);

#endif //AZRAEL_IMPLANT_LOADLIBRARY_H
