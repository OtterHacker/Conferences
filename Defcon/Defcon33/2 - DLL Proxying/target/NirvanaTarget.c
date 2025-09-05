#include <stdio.h>
#include <windows.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten OPTIONAL);

int main(void) {
    LoadLibraryA("libcrypto.dll");
    PVOID address = NULL;
    do {
        address = VirtualAlloc(NULL, 10000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(!address) {
            printf("[x] TARGET: Failed to allocate the memory...");
        }
    }while(address == NULL);
    printf("[+] TARGET: Memory allocated at %p!\n", address);
    char flag[] = "THIS IS MY PAYLOAD BRO\n";
    SIZE_T szOutput = 0;

    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (PVOID)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NTSTATUS result = NtWriteVirtualMemory((HANDLE)-1, address, flag, sizeof(flag), &szOutput);


    if(NT_SUCCESS(result) == 0) {
        printf("[x] TARGET: Failed to write in the memory space\n");
        exit(0);
    }
    printf("[+] TARGET: Successfully wrote the FLAG\n[+] TARGET: Starting thread\n");
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)address, NULL, 0, NULL);
    while(1){}
    return 0;
}