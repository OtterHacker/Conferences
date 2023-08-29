#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

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
	dllThread = CreateRemoteThread(processHandle, NULL, 0, threadRoutine, remoteBuffer, 0, NULL);
	if (!dllThread) {
		DEBUG("[x] Cannot create the remote thread\n");
		return FALSE;
	}

    // Wait for the DLL to be loaded, and return.
	WaitForSingleObject(dllThread, 1000);
	return TRUE;
}