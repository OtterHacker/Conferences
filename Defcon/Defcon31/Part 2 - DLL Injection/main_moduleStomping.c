#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>
#include "sc.h"

#define DLLPATH L"C:\\windows\\system32\\winmde.dll"
#define DLLNAME "winmde.dll"

int main(void) {
    /*************************************************************/
    /* The goal is to implement a self injector that will load a */
    /* new DLL in its process and write a malicious payload in a */
    /* given function in the DLL and then execute it             */
    /*************************************************************/

    // First Step: Retrieve the payload
    // Hints : Use one of the technique used in step 1


    // Second Step: Load the DLL in the process
    // Hints : LoadLibraryW is an interesting function
    // Hands on : Check in process hacker if the DLL has been well injected
    //            Look at the allocated memory step, what is different compared to a
    //            standard VirtualAlloc ?


    // Third Step: Retrieve the function address
    // Hints: GetProcAddress should do the job
    // Hands on : Find with PEBear an interesting function that can be stomped


    // Fourth Step: Stomp the function with the malicious payload
    // Hints: WriteProcessMemory should be ok


    // Fifth Step: Call the function
    // Hints: Cast the address to a function pointer ((void(*)())functionAddress)();    
    // Hands on: Set un breakpoint on the process and look at the thread stack
}