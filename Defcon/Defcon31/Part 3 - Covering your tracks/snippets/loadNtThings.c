#include "headers.h"

/****************************************************************/
/* This function resolve the Nt functions and store them in the */
/* NTDLLAPI structure for further use                           */
/****************************************************************/
BOOLEAN loadNtThings(NTDLLAPI* ntdll) {
    ntdll->ntdll = GetModuleHandle("NTDLL.DLL", NULL);
    if (!ntdll) { return FALSE; }
    ntdll->api.NtOpenProcess = GetProcAddress(ntdll->ntdll, "NtOpenProcess");
    ntdll->api.NtWriteVirtualMemory = GetProcAddress(ntdll->ntdll, "NtWriteVirtualMemory");
    ntdll->api.NtReadVirtualMemory = GetProcAddress(ntdll->ntdll, "NtReadVirtualMemory");
    ntdll->api.NtProtectVirtualMemory = GetProcAddress(ntdll->ntdll, "NtProtectVirtualMemory");
    ntdll->api.NtAllocateVirtualMemory = GetProcAddress(ntdll->ntdll, "NtAllocateVirtualMemory");
    ntdll->api.NtCreateThreadEx = GetProcAddress(ntdll->ntdll, "NtCreateThreadEx");
    ntdll->api.NtFreeVirtualMemory = GetProcAddress(ntdll->ntdll, "NtFreeVirtualMemory");
    ntdll->api.RtlNtStatusToDosError = GetProcAddress(ntdll->ntdll, "RtlNtStatusToDosError");

    ntdll->k32 = GetModuleHandle("KERNEL32.DLL", NULL);
    ntdll->api.ReadFile = GetProcAddress(ntdll->k32, "ReadFile");
    ntdll->api.CloseHandle = GetProcAddress(ntdll->k32, "CloseHandle");
    ntdll->api.GetLastError = GetProcAddress(ntdll->k32, "GetLastError");
    return TRUE;
}
