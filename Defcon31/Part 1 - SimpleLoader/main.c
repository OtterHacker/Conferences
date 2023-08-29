/*
 * You should be able to finish the workshop with writing any line of C.
 * All the code you need has been already written and splitted in the snippets files.
 * You should just copy the right code at the right place. The goal is for you to understand
 * what the code does and where it should be used and not redevelopping the whole malware.
 */

#include <windows.h>
#include "sc.h"

int main(void) {

    buildsc();
    /************************************************************/
    /* The goal is to implement a simple shellcode injection in */
    /* a remote process.                                        */
    /* You can use all the snippet in the snipper directory     */
    /************************************************************/

    // Last step : Dynamic API resolution
    // Hands on : Explore the PE import table
    // Hands on : Remove the WINAPI imports from the import table
    // Tips : Use the GetModuleHandleA and GetProcAddress functions
    //        All function definitions are given in the code snippets

    // First step : Retrieve the payload stored in the .data
    // Hands on : Store the payload in the .data section
    // Hint : use the encryptor.py file that take the .bin shellcode as parameter and create the sc.h file
    //        that can be used to store the payload in the .data section
    // Hands on : Once compiled, analyse the PE with PEbear and the Sysinternal String. Do you see your
    //            payload ? Can you see it in the .data section ?
    // Hands on : What happen if you try to hide the demon.bin ? Why is there a detection from Defender ?

    // Hands on (at the end): You can try to split it in the .data and .rdata section
    // Hint: In C the use of const parameter can be used to tell the compiler that the variable is 
    //        is readonly and will be stored in the .rdata section.

    // Hands on (at the end): Encrypt with a simple XOR encryption

    // Hands on (at the end): Implement some entropy evasion
    // Hands on (at the end): Does it change the binary entropy ? Why ? How is it possible to fix this ?

    // Second step : Open an handle on the remote process

    // Third step : Allocate memory on the remote process
    // Hands on : Check with process hacker what happend 
    //            in the process memory. 
    //            Change the initial permissions
    // Tips : Use the VirtualAllocEx function with PAGE_REDWRITE permission

    // Fourth step : Write the payload in memory
    // Hands on : Check with process hacker if the payload 
    //            has been successfully written (it should be the only one with RWX protection)
    // Tips : Use the WriteProcessMemory

    // Fifth step : Reprotect the memory
    // Tips : Use the VirtualProtectEx with PAGE_EXECUTE_READWRITE permission

    // Sixth step : Run the payload in a new thread
    //              Put a breakpoint in the injected process
    //              and look at its threadstack
    // Tips : Use CreateRemoteThread :
    //        CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    return 0;
}