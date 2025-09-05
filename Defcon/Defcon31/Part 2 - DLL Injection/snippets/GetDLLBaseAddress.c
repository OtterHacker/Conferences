#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

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