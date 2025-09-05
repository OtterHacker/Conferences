#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <DbgHelp.h>


#pragma comment(lib, "DbgHelp.lib")

#define ProcessInstrumentationCallback 40

typedef struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
        _In_ HANDLE hProcess,
        _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
        _In_reads_bytes_(ProcessInformationSize) LPVOID ProcessInformation,
        _In_ DWORD ProcessInformationSize
);

typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)(
        HANDLE    ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T   RegionSize,
        ULONG     AllocationType,
        ULONG     Protect
);

/*
 * ASM code used to setup the initial NirvanaHook
 * The function is defined in *hook.asm* file
 */
extern VOID InstrumentationHook(VOID);

/*
 * Check if the *needle* substring is in the *haystack* string
 * Return 1 if the *needle* is found, 0 otherwise.
 */
int issubstr(const char* haystack, const char* needle) {
    int haystackLen = strlen(haystack);
    int needleLen = strlen(needle);

    for (int i = 0; i <= haystackLen - needleLen; i++) {
        int j;
        for (j = 0; j < needleLen; j++) {
            if (tolower(haystack[i + j]) != tolower(needle[j]))
                break;
        }
        if (j == needleLen) // If entire needle is matched
            return 1;
    }
    return 0;
}

/*
 * Inspired by A.Ionescu intial work on Nirvana Hooking
 */
DWORD64 InstrumentationCHook(DWORD64 calling_function, DWORD64 initial_sysret){
    // We use this variable to avoid recursive hook execution.
    // The variable is defined at 0, and will be set to 1 when the Nirvana Hook is
    // executed.
    // When this value is 1, the NirvanaHook will just return without performing
    // any action.
    static BOOLEAN stop_recursive_call = 0;
    DWORD64 result = initial_sysret;

    // This is the condition needed to avoid recursive call
    // to the Nirvana hook
    if (stop_recursive_call == 0){
        int symbol_resolving_status;
        DWORD64 symbol_displacement = 0;
        PSYMBOL_INFO symbol = (PSYMBOL_INFO)calloc(1, sizeof(SYMBOL_INFO) + MAX_SYM_NAME);

        // We ensure that no additional NirvanaHook will be processed
        stop_recursive_call = 1;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        // We resolve the symbol for the calling function. It will allow
        // to perform conditional action depending on which function has
        // triggered the hook
        symbol_resolving_status = SymFromAddr((HANDLE)-1, calling_function, &symbol_displacement, symbol);

        // The hook has been triggered by NtAllocateVirtualMemory.
        // We can change the SYSRET now
        if (symbol_resolving_status && issubstr(symbol->Name, "AllocateVirtualMemory")) {
            printf("[+] Catched Syscall Response from ! %p (%s+%lx) [SYSRET Code = %08lX]\n", calling_function, symbol->Name, symbol_displacement, initial_sysret);
            // The SYSRET is changed to 0xc0000005 (FAILURE)
            result = 0xc0000005;
        }

        free(symbol);
        stop_recursive_call = 0;
    }

    // The modified SYSRET is returned to the program
    if (result != initial_sysret) {
        printf("[+] Patching SYSRET code... New SYSRET Code : %2x\n", result);
    }
    return result;
}



int main(void) {
    // No need to care for this line. It is used to allow DBGHelp to
    // resolve the symbols
    BOOL result = SymInitialize((HANDLE)-1, NULL, TRUE);

    // Setup the NirvanaHook
    HMODULE NTDLL = GetModuleHandle("ntdll.dll");
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
    // This function will be used to setup the NirvanaHook
    pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(NTDLL, "NtSetInformationProcess");
    // This function will be used to trigger the NirvanaHook
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(NTDLL, "NtAllocateVirtualMemory");

    // Define the function that will be called by the
    // Nirvana Hook
    InstrumentationCallbackInfo.Version = 0;
    InstrumentationCallbackInfo.Reserved = 0;
    InstrumentationCallbackInfo.Callback = InstrumentationHook;

    // Initial call without the Nirvana hook setup
    // The NtAllocateVirtualMemory call should succeed
    printf("[+] Without Nirvana Hook\n");
    PVOID baseAddress = NULL;
    SIZE_T pageSize = 300;
    NTSTATUS ntStatus = NtAllocateVirtualMemory((HANDLE)-1, &baseAddress, 0, &pageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(ntStatus)) {
        printf("[+] NtAllocateVirtualMemory success [SYSRET code = %08lX] \n\n", ntStatus);
    }
    else {
        printf("\n[x] Failed to allocate memory at %p with RWX protection [SYSRET code = %08lX] \n\n", baseAddress, ntStatus);
    }


    // Now we are installing the NirvanaHook
    printf("[+] With Nirvana Hook\n");
    LONG Status = NtSetInformationProcess(
            (HANDLE)-1,
            ProcessInstrumentationCallback,
            &InstrumentationCallbackInfo,
            sizeof(InstrumentationCallbackInfo)
    );

    // Second NtAllocateVirtualMemory call with the Nirvana Hook.
    // The hook should change the SYSRET code, the program will
    // think that the call failed.
    baseAddress = NULL;
    pageSize = 300;
    ntStatus = NtAllocateVirtualMemory((HANDLE)-1, &baseAddress, 0, &pageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(ntStatus)) {
        printf("Okk\n");
    }
    else {
        printf("\n[x] Failed to allocate memory at %p with RWX protection [SYSRET code = %08lX] \n\n", baseAddress, ntStatus);
    }
    while(1){}
}
