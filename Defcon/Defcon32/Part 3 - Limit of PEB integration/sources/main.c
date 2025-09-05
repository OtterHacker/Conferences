#include <stdio.h>
#include "loadlibrary.h"
#include <windows.h>

DECLARE_HANDLE(HAMSICONTEXT);
typedef HRESULT(NTAPI* pAmsiInitialize)(
        LPCWSTR      appName,
        HAMSICONTEXT* amsiContext
);


int main() {
    HMODULE bcrypt = load_library_a("C:\\Windows\\System32\\bcrypt.dll");

    exit(0);
    HAMSICONTEXT amsiContext = NULL;
    HMODULE amsi = load_library_a("C:\\Windows\\System32\\amsi.dll");
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
