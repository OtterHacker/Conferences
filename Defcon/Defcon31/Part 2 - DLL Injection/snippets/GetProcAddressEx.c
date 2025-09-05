#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

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