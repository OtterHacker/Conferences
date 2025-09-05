#ifndef AZRAEL_IMPLANT_MSVC_API_DEFINITION_H
#define AZRAEL_IMPLANT_MSVC_API_DEFINITION_H
#include <WS2tcpip.h>
#include <winhttp.h>
#include "peb.h"
#include <stdio.h>
#include <Psapi.h>

#define NTSTATUS LONG

typedef void *(__cdecl *MSVC$realloc)(void *_Memory,size_t _NewSize);
typedef void *(__cdecl *MSVC$calloc)(size_t _NumOfElements,size_t _SizeOfElements);
typedef void *(__cdecl *MSVC$memset)(void *_Dst,int _Val,size_t _Size);
typedef void *(__cdecl *MSVC$memcpy)(void * _Dst,const void * _Src,size_t _Size);
typedef void (__cdecl *MSVC$free)(void* _Memory);

typedef char *(__cdecl *MSVC$strdup)(const char *_Src);
typedef int (__cdecl *MSVC$strcmp)(const char *_Str1,const char *_Str2);
typedef size_t (__cdecl *MSVC$strlen)(const char *_Str);
typedef int (__cdecl *MSVC$stricmp)(const char *_Str1,const char *_Str2);
typedef int (__cdecl *MSVC$strncmp)(const char *_Str1,const char *_Str2,size_t _MaxCount);
typedef char * (__cdecl *MSVC$strcpy)(char * _Dest,const char * _Source);
typedef char * (__cdecl *MSVC$strtok)(char * _Str,const char * _Delim);
typedef char* (__cdecl *MSVC$strncpy)(char * _Destination, char* const _Src, size_t _Count);
typedef char* (*MSVC$strchr)(char* const _Str, int _Val);
typedef char * (__cdecl *MSVC$strcat)(char * _Dest,const char *_Source);
typedef size_t (__cdecl *MSVC$mbstowcs)(wchar_t *_Dest,const char * _Source,size_t _MaxCount);
typedef size_t (__cdecl *MSVC$wcstombs)(char *_Dest,const wchar_t *_Source,size_t _MaxCount);
typedef int (__cdecl *MSVC$wcsicmp)(const wchar_t *_Str1,const wchar_t *_Str2);
typedef size_t (__cdecl *MSVC$wcslen)(const wchar_t *_Str);
typedef wchar_t * (__cdecl *MSVC$wcscat)(wchar_t * _Dest,const wchar_t * _Source);
typedef int (__cdecl *MSVC$wcscmp)(const wchar_t *_Str1,const wchar_t *_Str2);
typedef wchar_t * (__cdecl *MSVC$wcscpy)(wchar_t * _Dest,const wchar_t * _Source);

typedef int (__CRTDECL *MSVC$vsprintf)(char* const _Buffer, char const* const _Format, va_list _ArgList);

typedef int (*MSVC$printf) (const char *__format, ...);
typedef int (*MSVC$scanf)(const char *__format, ...);
typedef int (*MSVC$swprintf) (wchar_t *__stream, size_t __count, const wchar_t *__format, ...);
typedef int (__CRTDECL *MSVC$vsnprintf)(char* const _Buffer,size_t const _BufferCount,char const* const _Format,va_list _ArgList);
typedef int (__CRTDECL *MSVC$vprintf)(char const* const _Format, va_list _ArgList);

typedef DWORD (WINAPI *MSVC$GetLastError) (VOID);
typedef HMODULE (WINAPI *MSVC$LoadLibraryExA) (LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
typedef HMODULE (WINAPI *MSVC$LoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
typedef LPVOID (WINAPI *MSVC$VirtualAlloc) (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *MSVC$VirtualProtect) (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef BOOL (WINAPI *MSVC$VirtualFree) (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);


typedef HINTERNET   (WINAPI *MSVC$WinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET   (WINAPI *MSVC$WinHttpConnect)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET   (WINAPI *MSVC$WinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL      (WINAPI *MSVC$WinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI *MSVC$WinHttpReceiveResponse)(HINTERNET,LPVOID);
typedef BOOL      (WINAPI *MSVC$WinHttpQueryDataAvailable)(HINTERNET,LPDWORD);
typedef BOOL      (WINAPI *MSVC$WinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI *MSVC$WinHttpAddRequestHeaders)(HINTERNET,LPCWSTR,DWORD,DWORD);
typedef BOOL      (WINAPI *MSVC$WinHttpCloseHandle)(HINTERNET);
typedef FARPROC (WINAPI *MSVC$GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef int  (WSAAPI *MSVC$WSACleanup)(void);
typedef int  (WSAAPI *MSVC$ioctlsocket)(SOCKET s,long cmd,u_long *argp);

typedef int (WSAAPI *MSVC$connect)(SOCKET s,const struct sockaddr *name,int namelen);
typedef SOCKET (WSAAPI *MSVC$accept)(SOCKET s,struct sockaddr *addr,int *addrlen);
typedef int  (WSAAPI *MSVC$bind)(SOCKET s,const struct sockaddr *name,int namelen);
typedef int  (WSAAPI *MSVC$closesocket)(SOCKET s);
typedef int  (WSAAPI *MSVC$recv)(SOCKET s,char *buf,int len,int flags);
typedef int  (WSAAPI *MSVC$send)(SOCKET s,const char *buf,int len,int flags);
typedef int  (WSAAPI *MSVC$WSAStartup)(WORD wVersionRequested,LPWSADATA lpWSAData);
typedef int  (WSAAPI *MSVC$listen)(SOCKET s,int backlog);
typedef int  (WSAAPI *MSVC$WSAGetLastError)(void);
typedef int  (WSAAPI *MSVC$shutdown)(SOCKET s,int how);
typedef SOCKET (WSAAPI *MSVC$socket)(int af,int type,int protocol);
typedef int  (WSAAPI *MSVC$getaddrinfo)(const char *nodename,const char *servname,const struct addrinfo *hints,struct addrinfo **res);
typedef void  (WSAAPI *MSVC$freeaddrinfo)(LPADDRINFO pAddrInfo);

typedef SIZE_T (WINAPI *MSVC$VirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef BOOL (WINAPI *MSVC$ReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
typedef BOOL (WINAPI *MSVC$WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef LPVOID (WINAPI *MSVC$HeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef HANDLE (WINAPI *MSVC$HeapCreate)(DWORD flOptions,SIZE_T dwInitialSize,SIZE_T dwMaximumSize);
typedef BOOL (WINAPI *MSVC$HeapFree)(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem);
typedef LPVOID (WINAPI *MSVC$HeapReAlloc)( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
typedef BOOL (WINAPI *MSVC$HeapDestroy)(HANDLE hHeap);

typedef void (NTAPI *MSVC$RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS (NTAPI *MSVC$NtQuerySystemTime)(PLARGE_INTEGER SystemTime);
typedef NTSTATUS (NTAPI *MSVC$RtlHashUnicodeString)(UNICODE_STRING* String, BOOLEAN CaseInSensitive, ULONG HashAlgorithm, ULONG* HashValue);
typedef void (WINAPI* MSVC$RtlRbInsertNodeEx)(PRTL_RB_TREE Tree, PRTL_BALANCED_NODE Parent, BOOLEAN Right, PRTL_BALANCED_NODE Node);
typedef PVOID (WINAPI *MSVC$ResolveDelayLoadedAPI)(PVOID ParentModuleBase, PCIMAGE_DELAYLOAD_DESCRIPTOR DelayloadDescriptor, PVOID FailureDllHook, PVOID FailureSystemHook, PIMAGE_THUNK_DATA ThunkAddress, ULONG Flags);


typedef LONG (NTAPI *MSVC$RtlCompareUnicodeStrings)(PWCH String1, SIZE_T String1Length, PWCH String2, SIZE_T String2Length,BOOLEAN CaseInSensitive);

typedef BOOL (WINAPI *MSVC$WinHttpGetDefaultProxyConfiguration)(WINHTTP_PROXY_INFO * pProxyInfo);



typedef DWORD (WINAPI *MSVC$SearchPathW)(LPCWSTR lpPath,LPCWSTR lpFileName,LPCWSTR lpExtension,DWORD nBufferLength,LPWSTR lpBuffer,LPWSTR* lpFilePart);
typedef HANDLE (WINAPI *MSVC$CreateFileW)(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile);
typedef BOOL (WINAPI *MSVC$ReadFile)(HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,LPOVERLAPPED lpOverlapped);
typedef DWORD (WINAPI *MSVC$GetFileSize)(HANDLE hFile,LPDWORD lpFileSizeHigh);
typedef void* (__cdecl *MSVC$memmove)(void* _Dst,void const* _Src,size_t _Size);
typedef BOOL (WINAPI *MSVC$FlushInstructionCache)(HANDLE hProcess,LPCVOID lpBaseAddress,SIZE_T dwSize);
typedef BOOLEAN (__cdecl *MSVC$RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable,DWORD EntryCount,DWORD64 BaseAddress);
typedef BOOL (WINAPI *MSVC$CloseHandle)(HANDLE hObject);
typedef HANDLE (WINAPI *MSVC$GetProcessHeap)(VOID);

typedef NTSTATUS(NTAPI *MSVC$NtSetInformationProcess)(HANDLE hProcess, PROCESS_INFORMATION_CLASS ProcessInformationClass, LPVOID ProcessInformation, DWORD ProcessInformationSize);
typedef NTSTATUS(NTAPI *MSVC$NtContinue)(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
typedef NTSTATUS(NTAPI *MSVC$LdrLockLoaderLock) (ULONG Flags, ULONG *State, unsigned __int64 *Cookie);
typedef NTSTATUS(NTAPI *MSVC$LdrUnlockLoaderLock) (ULONG Flags, unsigned __int64 Cookie);

typedef VOID (NTAPI *MSVC$RtlCaptureContext)(PCONTEXT ContextRecord);
typedef VOID (WINAPI *MSVC$GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime);

typedef HANDLE (WINAPI *MSVC$CreateThread)( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

typedef FILE* (__cdecl *MSVC$fopen)(char const* _FileName, char const* _Mode);
typedef int (__cdecl *MSVC$fseek)(FILE* _Stream, long  _Offset, int   _Origin);
typedef int (__cdecl *MSVC$fclose)(FILE* _Stream);
typedef size_t (__cdecl *MSVC$fread)(void*  _Buffer, size_t _ElementSize, size_t _ElementCount, FILE*  _Stream);
typedef int (__cdecl *MSVC$feof)(FILE* _Stream);
typedef size_t (__cdecl *MSVC$fwrite)( void const* _Buffer, size_t _ElementSize, size_t _ElementCount, FILE* _Stream);
typedef int (__cdecl *MSVC$ferror)(FILE *_File);
typedef VOID (WINAPI *MSVC$ExitThread)(DWORD dwExitCode);
typedef DWORD (WINAPI *MSVC$SetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
typedef HANDLE (WINAPI *MSVC$CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL (WINAPI *MSVC$WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef int (WINAPI *MSVC$MultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
typedef void *(WINAPI *MSVC$RtlFillMemory_)(void *_Dst,size_t _Size, int _Val);
typedef VOID (WINAPI *MSVC$Sleep)(DWORD dwMilliseconds);
typedef BOOL (WINAPI *MSVC$GetUserNameA)(LPSTR lpBuffer, LPDWORD pcbBuffer);

typedef char FAR *(WSAAPI *MSVC$inet_ntoa)(struct in_addr in);
typedef struct hostent FAR *(WSAAPI *MSVC$gethostbyname)(const char FAR * name);
typedef int (WSAAPI *MSVC$gethostname)(char FAR * name, int namelen);
typedef BOOL (WINAPI *MSVC$GetComputerNameExA)(COMPUTER_NAME_FORMAT NameType, LPSTR lpBuffer, LPDWORD nSize);
typedef DWORD (*MSVC$K32GetProcessImageFileNameA)( HANDLE hProcess, LPSTR  lpImageFileName, DWORD  nSize);
typedef DWORD (WINAPI *MSVC$GetCurrentProcessId)(VOID);
typedef BOOL (WINAPI *MSVC$OpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef BOOL (WINAPI *MSVC$GetTokenInformation)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);

typedef int (WSAAPI *MSVC$WSAPoll)(LPWSAPOLLFD fdArray,ULONG fds,INT timeout);

//typedef HRESULT (*MSVC$CLRCreateInstance)(REFCLSID clsid,REFIID riid,LPVOID* ppInterface);

#endif //AZRAEL_IMPLANT_MSVC_API_DEFINITION_H