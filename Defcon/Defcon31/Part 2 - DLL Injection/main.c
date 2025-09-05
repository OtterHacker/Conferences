int main(void){
    /*************************************************************/
    /* The goal is to implement a injector that will load a DLL  */
    /* in a remote process and  use the allocated space to write */
    /* the malicious shellcode.                                  */
    /*************************************************************/


    // First Step: Retrieve the payload
    // Hints : Use one of the technique used in step 1

    // Second Step: Retrieve the process handle
    // Hints : Use the getProcHandlebyName function

    // Third step: Inject the DLL in the remote process
    // Hints : Exactly like module stomping, but now target a remote process
    //         Look at the injectDLL function
    // Hands On : Look with process hacker if the DLL has been well loaded
    //            Put un breakpoint on LoadLibraryW in the injected process and 
    //            check the injected process thread stack

    // Fourth step: Retrieve the DLL base address
    // Hints : Like a GetModuleHandle, but on a remote process
    //         The EnumProcessModules function can be used to enumerate all DLL
    //         loaded by a process.

    // Fifth step: Retrieve the function address that will be stomped
	// Hints : Like a GetProcAddress but on a remote process
    //         The DLL exported address RVA are stored in the DLL exportDirectory.
    //         Retrieving the DLL PE header is the first step.
    //         Look at the getProcAddressEx function


    // Sixth step: Stomp the function with your malicious code
    // Hints : We are just writting some byte on a specific address here and run it using CreateRemoteThread
    // HandsOn : Check the threadstack on the injected process
}