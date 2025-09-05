#include "common.h"
#include "hook.h"
#include "utils.h"

#define ProcessInstrumentationCallback 40

#include <intrin.h>

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION{
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

extern VOID InstrumentationHook(VOID);

DWORD_PTR           initialRsp;
CONTEXT             threadCtxBackup;
PVOID               stackBackup;
DWORD               stackBackupSize;
DWORD64             systemTime;
DWORD64             sleepTime;


/*
 * The Nirvana Hook C code that will be called
 */
DWORD64 InstrumentationCHook(DWORD64 Function, DWORD64 ReturnValue){
    static BOOLEAN g_Recurse = 0;
    DWORD64 result = ReturnValue;
    if (g_Recurse == 0){
        g_Recurse = 1;
        // TODO: set the right condition so that the the program is waked up
        //       only after sleepTime seconds
        // Hint: The getEpoch() function return the current time
        DWORD64 currentSystemTime = getEpoch();
        if(currentSystemTime - systemTime > sleepTime){
            printf("[+] Waking up\n");
            // TODO: Add a command to avoid the hook to be called multiple time
            //       when the program is awake
            // Hint: To remove a hook, you can set the callback function to NULL
            InstallNirvana(NULL);
            printf("[+] Starting new thread\n");

            // TODO: Fix this call so that is create a thread a respawn the thread
            // Hint: The awake function is used to respawn the thread. Check the arguments
            //       the awake function expect a thread context
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)awake, &threadCtxBackup, 0, NULL);
        }
        g_Recurse = 0;
    }
    return result;
}


/*
 * Simple helper to get the current time
 */
DWORD64 getEpoch(){
    FILETIME fileTime;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&fileTime);
    uli.LowPart = fileTime.dwLowDateTime;
    uli.HighPart = fileTime.dwHighDateTime;
    return uli.QuadPart / 10000000ULL - 11644473600ULL;
}


/*
 * This function is used to start the initial program or
 * awake a killed thread.
 * The lpParam attribute contains the thread context needed
 * by NtContinue
 */
VOID awake(PVOID lpParam){
    DWORD64 oldRspEnd = initialRsp;
    DWORD64 oldRspStart = initialRsp - stackBackupSize;
    initialRsp = getRsp();

    if (lpParam != NULL){
        // Parse the old stack and perform pointer relocation
        // If a pointer look like pointing to an address of the
        // old stack we relocate it
        DWORD64 stackOffset = initialRsp - oldRspEnd;
        for(int i = 0; i < stackBackupSize; i += sizeof(PVOID)){
            // Check if the address point to something in the range
            // of the old stack
            if(*(DWORD64*)((DWORD64)stackBackup + i) < oldRspEnd && *(DWORD64*)((DWORD64)stackBackup + i) > oldRspStart){
                // If yes, we just add the offset to the pointer
                // so it now point on the new stack
                *(DWORD64*)((DWORD64)stackBackup + i) += stackOffset;
            }
        }

        // Use the ASM macro to move the whole stack
        // It can be done with memcpy, but it can add
        // some offset in the stack start/size that would
        // break something
        // // DWORD stack_frame_size  = GetStackFrameSize();
        // PVOID rsp = (PVOID)get_rsp();
        // // Compute the offset
        // DWORD64 offset = stack_frame_size + stack_backup_size + 0x28;
        // // Copy the stack
        // memcpy((PVOID)((DWORD64)rsp-2*offset),(PVOID)((DWORD64)rsp-offset), 0x28 + stackBackupSize);
        // // Set the new stack pointer
        // set_rsp((DWORD64)rsp-offset);
        // This is used to create a "hole" between the thread stack and the
        // awake stack
        // ________________________________________________
        // ThreadStart |                     |     AWAKE
        // ________________________________________________
        // Then we can simply copy the back stack in the hole created:
        // ________________________________________________
        // ThreadStart |     BACKUP STACK    |     AWAKE
        // ________________________________________________
        // It avoids having a stack like this when the awake function stack grows
        // ____________________________________
        // ThreadStart | AWAKE  BACKUP STA | CK
        // ____________________________________

        // TODO: Fix the call to moveRsp
        // Hint: The stack address where the return address of the current is
        //       stored can be accessed using _AddressOfReturnAddress() function
        //       moveRsp(sizeToIncrease, epilogueSize)
        moveRsp(stackBackupSize, (DWORD64)_AddressOfReturnAddress() - getRsp());

        printf("[-] Setting up the stack\n");
        void (*NtContinue)(PCONTEXT, BOOLEAN);
        NtContinue = (PVOID)GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue");

        // We can now copy the whole stack
        // TODO: Fix this call to copy the stack
        // Hint: Remember the direction where the stack grows...
        memcpy((PVOID)(initialRsp - stackBackupSize), stackBackup, stackBackupSize);
        free(stackBackup);

        // We can change the RSP in the thread context
        // TODO: Fix this call to set the new RSP pointer
        ((PCONTEXT)lpParam)->Rsp = (DWORD64)(initialRsp - stackBackupSize);

        // TODO: Restore the thread wit NtContinue
        NtContinue(lpParam, FALSE);
    }
    else{
        mainProgram();
    }
}

/*
 * This function is used to install a NirvanaHook.
 * It takes the function that must be used as a hook as a parameter.
 */
int InstallNirvana(PVOID hook){
    printf("[+] Modify Nirvana Hook\n");

    if(hook){
        systemTime = getEpoch();
    }

    HMODULE NTDLL = GetModuleHandle("ntdll.dll");
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
    pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(NTDLL, "NtSetInformationProcess");
    InstrumentationCallbackInfo.Version = 0;
    InstrumentationCallbackInfo.Reserved = 0;
    InstrumentationCallbackInfo.Callback = hook;

    return NtSetInformationProcess(
            (HANDLE) -1,
            ProcessInstrumentationCallback,
            &InstrumentationCallbackInfo,
            sizeof(InstrumentationCallbackInfo)
    );
}


/*
 * Simple wrapper that allows to emulate a sleep
 */
VOID NirvanaSleep(ULONGLONG time){
    DWORD stackFrameSize  = (DWORD64)_AddressOfReturnAddress() - getRsp();
    sleepTime = time;
    RtlCaptureContext(&threadCtxBackup);

    // We set RIP so that the execution flow is restored after the calling
    // function: ie the return address of the current function
    // (RIP address stored on RSP + stackFrameSize)
    // TODO: Change the Thread RIP so that it allows a smooth return
    //       to execution
    // Hint: The address of return of a function is stored right after
    //       its stackframe...
    threadCtxBackup.Rip = *(PDWORD64)(threadCtxBackup.Rsp + stackFrameSize);
    stackBackupSize = initialRsp - (threadCtxBackup.Rsp + stackFrameSize + 0x8);
    stackBackup = malloc(stackBackupSize);
    memcpy(stackBackup, (PVOID)(initialRsp - (DWORD64)stackBackupSize), stackBackupSize);
    InstallNirvana(InstrumentationHook);

    ExitThread(0);
}

DWORD WINAPI mainProgram()
{
    int c = 0;
    int j = 0;
    while (1)
    {
        printf("[+] Going to sleep\n");
        NirvanaSleep(5);
        printf("\t[-] Beacon awoken and performing its action\n");
        printf("\t[-] Global value : %d\n", c);
        Sleep(1000);
        c++;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    printf("[+] Press a key to start\n");
    getchar();

    // Create the initial thread
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)awake, NULL, 0, NULL);

    // This is just to ensure SYSCALL will be performed
    // on a regular basis
    while(1){
        PVOID a = VirtualAlloc(NULL, 10, MEM_COMMIT, PAGE_READWRITE);
        BOOL result = VirtualFree(a, 0, MEM_RELEASE);
        if(!result){
            printf("Failed %d\n", GetLastError());
            exit(0);
        }
    }

}
