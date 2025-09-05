# Part 4 - Delayed loading and IAT

# Main objectives
Learn how to hijack IAT at DLL load.
Learn more about delayed loading and find a way to limit do a just-in-time DLL loading

# IAT Hijacking
Look at the code from `Part 3`. In which function IAT hijacking can be implemented ?

Implement a basic IAT hijacking by hijacking the `AmsiInitialize` function : make it print a random message, for example.

# Delayed Loading
## Identify the function handling the Delayed Loading
Take the code of Step 1 and load the AMSI.dll with LoadLibraryA. Add a stop point (getchar()) right after loading the DLL:
```c
#include <windows.h>
DECLARE_HANDLE(HAMSICONTEXT);
typedef HRESULT(NTAPI* pAmsiInitialize)(
        LPCWSTR      appName,
        HAMSICONTEXT* amsiContext
);

int main() {
    HAMSICONTEXT amsiContext = NULL;
    HMODULE amsi = LoadLibraryA("C:\\Windows\\System32\\amsi.dll");
    getchar();
    pAmsiInitialize AmsiInitialize = (pAmsiInitialize)GetProcAddress((HMODULE)amsi, "AmsiInitialize");
    if (!AmsiInitialize) {
        printf("Cannot load the function\n");
        return 0;
    }
    else {
        printf("[+] AmsiInitialize address : 0x%p\n", AmsiInitialize);
    }

    HRESULT result = AmsiInitialize(L"Test", &amsiContext);
    if(result == S_OK){
        printf("[+] AMSI Initialize succeed !\n");
    }
    else{
        printf("[+] AMSI Initialize error !\n");
    }

    return 0;
}
```

Run the program and attach WinDBG.

In WinDBG add a breakpoint on LdrLoadDll `bp ntdll!LdrLoadDll`.

Resume the program.

When the breakpoint is hit, find the function that is responsible for handling the Delayed DLL Loading.

## Implement a workaround in the custom Loader
Using the IAT hijacking, fix the custom loader code of Step 4 to smoothly handle the delayed loading.

You will have to do some reverse engineering on the ntdll/kernel32 DLL in order to find some information.

