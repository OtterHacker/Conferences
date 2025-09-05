#include <windows.h>

typedef HANDLE(WINAPI* pOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

typedef LPVOID(WINAPI* pVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

typedef BOOL(WINAPI* pWriteProcessMemory)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);

typedef BOOL(WINAPI* pVirtualProtectEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);

typedef HANDLE(WINAPI* pCreateRemoteThread)(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);

pOpenProcess openProcess;
pVirtualAllocEx virtualProtectEx;
pWriteProcessMemory writeProcessMemory;
pVirtualAllocEx virtualAllocEx;
pCreateRemoteThread createRemoteThread;