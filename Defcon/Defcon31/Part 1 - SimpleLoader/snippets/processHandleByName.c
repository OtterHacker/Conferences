#include <windows.h>
#include <TlHelp32.h>
#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

/************************************************************/
/* This function takes the name of a process and store its  */
/* PID in the PID parameter and return the process HANDLE   */
/* The PID is NULL if the function failed                   */
/*                                                          */
/* HANDLE proc = getProcHandlebyName("notepad.exe", &pid);  */
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
			// Note : _tcsicmp (include "tchar.h")
			if (stricmp((entry.szExeFile), procName) == 0) {
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
