#include "winapi.h"
#include <stdlib.h>
#include <string.h>
#include "peb.h"
#include "utils.h"
#include "loadlibrary.h"

unsigned long hash_string(void* buffer, size_t size, char* extension){
    if(buffer == NULL){
        return 0;
    }
    unsigned char current = 0;
    unsigned long hash = 0;
    unsigned char* currentChar = NULL;
    hash = 8392;
    currentChar = (void*)buffer;
    hash++;

    while(1){
        current = *currentChar;

        if (!size) {
            if (!*currentChar) {break;}
        }
        else {
            if ((ULONG)(currentChar - (PUCHAR)buffer) >= size) { break; }
            if (!*currentChar) { ++currentChar; continue; }
        }
        if (current >= 'a'){current -= 0x20;}
        hash = ((hash << 5) + hash) + current;
        ++currentChar;
    };

    if(extension) {
        currentChar = (void *)extension;
        while (1) {
            current = *currentChar;
            if (!*currentChar) { break; }

            if (current >= 'a') { current -= 0x20; }
            hash = ((hash << 5) + hash) + current;
            ++currentChar;
        };
    }
    return hash;
};

PLDR_DATA_TABLE_ENTRY get_ldr_entry(unsigned long module_hash){
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY hdr = NULL;
    PLIST_ENTRY ent = NULL;
    PLDR_DATA_TABLE_ENTRY ldr = NULL;
    hdr = &(peb->Ldr->InLoadOrderModuleList);
    ent = hdr->Flink;
    for (; hdr != ent; ent = ent->Flink){
        ldr = (void*)ent;
        //printf("%ls %x\n", ldr->BaseDllName.Buffer, hash_string(ldr->BaseDllName.Buffer, ldr->BaseDllName.Length, NULL));
        if (hash_string(ldr->BaseDllName.Buffer, ldr->BaseDllName.Length, NULL) == module_hash){
            return ldr;
        }
    }
    return NULL;
}

HMODULE get_module_handle(unsigned long module_hash, unsigned long* image_size) {
    PLDR_DATA_TABLE_ENTRY ldr = get_ldr_entry(module_hash);
    if(ldr){
        if (image_size != NULL) { *image_size = ldr->SizeOfImage; }
        return ldr->DllBase;
    }
    return NULL;
}

wchar_t* get_module_file_name(PVOID base_address){
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY hdr = NULL;
    PLIST_ENTRY ent = NULL;
    PLDR_DATA_TABLE_ENTRY ldr = NULL;
    hdr = &(peb->Ldr->InLoadOrderModuleList);
    ent = hdr->Flink;
    for (; hdr != ent; ent = ent->Flink){
        ldr = (void*)ent;
        if (ldr->DllBase == base_address){
            return ldr->BaseDllName.Buffer;
        }
    }
    return NULL;
}

PVOID get_proc_address_ordinal(HMODULE module_handle, unsigned int ordinal){
    if(!module_handle){
        return NULL;
    }
    PIMAGE_DOS_HEADER dosHeaders = (PVOID)module_handle;
    PIMAGE_NT_HEADERS  ntHeaders = (PVOID)((ULONG_PTR)dosHeaders + dosHeaders->e_lfanew);
    PIMAGE_DATA_DIRECTORY dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dataDirectory->VirtualAddress) {
        PIMAGE_EXPORT_DIRECTORY exportsDirectory = (PVOID) ((ULONG_PTR) dosHeaders + dataDirectory->VirtualAddress);
        if(ordinal - exportsDirectory->Base > exportsDirectory->NumberOfFunctions){
            return NULL;
        }
        ULONG idx = ordinal - exportsDirectory->Base;
        PUINT32 addressOfFunctions = (PVOID) ((ULONG_PTR) dosHeaders + exportsDirectory->AddressOfFunctions);
        if((addressOfFunctions[idx] >=dataDirectory->VirtualAddress) && (addressOfFunctions[idx] < dataDirectory->VirtualAddress + dataDirectory->Size)){
            // Get the name of the forwarder : DLL.FUNCTION
            char* forwarded_dll = (char*)((ULONG_PTR)dosHeaders + addressOfFunctions[idx]);
            return resolve_forwarded(module_handle, forwarded_dll);
        }
        return (PVOID) ((ULONG_PTR) dosHeaders + addressOfFunctions[idx]);
    }
    return NULL;
}

PVOID resolve_forwarded(HMODULE current_dll, char* forwarded_dll){
    // Retrieve the function name with a simple split on '.'
    char* export_name = forwarded_dll;
    while(*export_name != '.'){
        if(*export_name == '\0'){
            return NULL;
        }
        export_name++;
    }
    size_t dll_name_length = export_name - forwarded_dll;
    export_name++;

    ULONG export_hash = hash_string(export_name, 0, NULL);
    wchar_t *current_module_name = get_module_file_name(current_dll);
    wchar_t resolved_api[MAX_PATH];
    wchar_t api_to_resolve[MAX_PATH];
    int i = 0;
    while(forwarded_dll[i] != 0){
        api_to_resolve[i] = (wchar_t)forwarded_dll[i];
        i += 1;
    }
    api_to_resolve[i] = L'\0';
    int result = resolve_api_set(api_to_resolve, resolved_api, current_module_name);

    // Get the module handle
    HMODULE export_dll_module = result ? load_library_w(resolved_api) : load_library_a(forwarded_dll);

    // Resolve the forwarder and return the value
    return get_proc_address(export_dll_module, export_hash);
}

PVOID get_proc_address(HMODULE module_handle, unsigned long hash) {
    if(!module_handle){
        return NULL;
    }
    PIMAGE_DOS_HEADER dosHeaders = (PVOID)module_handle;
    PIMAGE_NT_HEADERS  ntHeaders = (PVOID)((ULONG_PTR)dosHeaders + dosHeaders->e_lfanew);
    PIMAGE_DATA_DIRECTORY dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    ULONG Idx = 0;
    if (dataDirectory->VirtualAddress){
        PIMAGE_EXPORT_DIRECTORY exportsDirectory = (PVOID)((ULONG_PTR)dosHeaders + dataDirectory->VirtualAddress);
        PUINT32 addressOfNames = (PVOID)((ULONG_PTR)dosHeaders + exportsDirectory->AddressOfNames);
        PUINT32 addressOfFunctions = (PVOID)((ULONG_PTR)dosHeaders + exportsDirectory->AddressOfFunctions);
        PUINT16 addressOfOrdinals = (PVOID)((ULONG_PTR)dosHeaders + exportsDirectory->AddressOfNameOrdinals);

        for (Idx = 0; Idx < exportsDirectory->NumberOfNames; ++Idx){
            //printf("#define %s 0x%x\n", (PVOID)((ULONG_PTR)dosHeaders + addressOfNames[Idx]), hash_string((PVOID)((ULONG_PTR)dosHeaders + addressOfNames[Idx]), 0));
            if (hash_string((PVOID)((ULONG_PTR)dosHeaders + addressOfNames[Idx]), 0, NULL) == hash){
                // Forwarded export
                if((addressOfFunctions[addressOfOrdinals[Idx]] >=dataDirectory->VirtualAddress) && (addressOfFunctions[addressOfOrdinals[Idx]] < dataDirectory->VirtualAddress + dataDirectory->Size)){
                    // Get the name of the forwarder : DLL.FUNCTION
                    char* forwarded_dll = (char*)((ULONG_PTR)dosHeaders + addressOfFunctions[addressOfOrdinals[Idx]]);
                    return resolve_forwarded(module_handle, forwarded_dll);
                }
                return (PVOID)((ULONG_PTR)dosHeaders + addressOfFunctions[addressOfOrdinals[Idx]]);
            }
        }
    }

    return NULL;
}