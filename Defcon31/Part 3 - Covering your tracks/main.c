#include <windows.h>
int main(void){
    /*************************************************************/
    /* The goal is to implement a injector that will load a DLL  */
    /* in a remote process and  use the allocated space to write */
    /* the malicious shellcode.                                  */
    /*************************************************************/

    // Take the code from the Part 2 and modify the differente CreateRemoteThread


    // Step2 : Modify the CreateRemotThread used for the remote DLL injection
    // Hint : You should store an additional shellcode on the remote process
    //        to run the LoadLibraryW(args)
    // Hands on: Same that for Step 1
    

    // Step 1 : Modify the final CreateRemotThread to check if still everything work fine
    // Hint : You can first try to target Notepad with a ReadFile trigger
    // Hands on : Follow the execution flow with a debugger
    //            Try to retrieve the hook and the trampoline
    //            Verify that the trampoline rewritte the hook on the fly
    //            What happened when the mailicious code has been successfully executed ?

}