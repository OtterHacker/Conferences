#include "winapi.h"
#include "loadlibrary.h"

PBYTE read_file_w(LPWSTR filename, PDWORD file_size) {
    HANDLE file_handle = CreateFileW(
            filename,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
    );
    if (file_handle == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    *file_size = GetFileSize(file_handle, NULL);
    DWORD sizeRead = 0;
    PBYTE content = (PBYTE)calloc(*file_size, sizeof(unsigned char));
    DWORD result = ReadFile(file_handle, content, *file_size, &sizeRead, NULL);
    if (!result || sizeRead != *file_size) {
        DEBUG_LOW("[x] read_file_w: error during %ls file read\n", filename);
        free(content);
        content = NULL;
    }
    CloseHandle(file_handle);
    return content;
}

/*
 * Helper that given a base address will map the element
 * in a structure representing the PE.
 */
PE *pe_create(PVOID image_base, BOOL is_memory_mapped) {
    PE *pe = (PE *)calloc(1, sizeof(PE));
    if (!pe) {
        DEBUG_LOW("[x] pe_create: error during PE allocation\n");
        return NULL;
    }

    pe->memoryMapped = is_memory_mapped;
    pe->dosHeader = image_base;
    pe->ntHeader = (IMAGE_NT_HEADERS *) ((PBYTE) image_base + pe->dosHeader->e_lfanew);
    pe->optionalHeader = &(pe->ntHeader->OptionalHeader);

    if (is_memory_mapped) {
        pe->baseAddress = image_base;
    } else {
        pe->baseAddress = (PVOID) pe->optionalHeader->ImageBase;
    }

    pe->dataDirectory = pe->optionalHeader->DataDirectory;
    pe->sectionHeader = (IMAGE_SECTION_HEADER *) ((PBYTE) (pe->optionalHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);

    DWORD export_directory_rva = (DWORD) pe->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_directory_rva == 0) {
        pe->exportDirectory = NULL;
        pe->AddressOfFunctions = NULL;
        pe->AddressOfNames = NULL;
        pe->AddressOfNameOrdinals = NULL;
        pe->NumberOfNames = 0;
    } else {
        pe->exportDirectory = resolve_rva(pe, export_directory_rva);
        pe->AddressOfFunctions = resolve_rva(pe, pe->exportDirectory->AddressOfFunctions);
        pe->AddressOfNames = resolve_rva(pe, pe->exportDirectory->AddressOfNames);
        pe->AddressOfNameOrdinals = resolve_rva(pe, pe->exportDirectory->AddressOfNameOrdinals);
        pe->NumberOfNames = pe->exportDirectory->NumberOfNames;
    }

    pe->relocations = NULL;
    return pe;
}


PVOID resolve_rva(PE *pe, DWORD64 rva) {
    if (pe->memoryMapped) {
        // If the PE is already mapped in memory, no need to perform
        // any computation. The rva is the offset from the file start
        return (PVOID) ((DWORD64) pe->dosHeader + rva);
    }

    // If the PE is not mapped in memory *ie read from file for example*
    // some work must be done to resolve the rva :
    // https://0xrick.github.io/win-internals/pe8/#resolving-rvas
    for (SIZE_T i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER *section = (PVOID) ((DWORD64) pe->sectionHeader + i * SECTION_SIZE);
        DWORD64 section_start = (DWORD64) section->VirtualAddress;
        DWORD64 section_end = section_start + section->Misc.VirtualSize;
        if ((DWORD64) rva >= section_start && (DWORD64) rva < section_end) {
            return (PVOID) ((DWORD64) pe->dosHeader + section->PointerToRawData + ((DWORD64) rva - section_start));
        }
    }
    return NULL;
}

/*
 * Read the DLL file to load and map the section in memory
 */
PVOID minimal_memory_map(LPWSTR filepath) {
    DWORD file_size = 0;
    PBYTE dll_content = read_file_w(filepath, &file_size);

    PVOID address = NULL;

    // Parse the file into a PE structure
    PE *dll_parsed = pe_create(dll_content, FALSE);
    if (!dll_parsed) {
        DEBUG_LOW("[x] minimal_memory_map: failed to parse the DLL\n");
        return NULL;
    }

    // Allocate a section to write the DLL
    PVOID start_address = VirtualAlloc(address, dll_parsed->ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!start_address) {
        DEBUG_LOW("[x] minimal_memory_map: cannot allocate DLL memory %lu\n", GetLastError());
        free(dll_parsed);
        return NULL;
    }
    DEBUG_LOW("[+] minimal_memory_map: memory allocated at : %p\n", start_address);
    DEBUG_LOW("[+] minimal_memory_map: copy headers in memory\n");

    // Copy the DLL header in the allocated section
    memcpy(start_address, dll_content, dll_parsed->ntHeader->OptionalHeader.SizeOfHeaders);

    DEBUG_LOW("[+] minimal_memory_map: copy sections in memory\n");
    // Copy each sections one by one in the allocated section
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(dll_parsed->ntHeader);
    for (DWORD i = 0; i < dll_parsed->ntHeader->FileHeader.NumberOfSections; i++, section_header++) {
        DEBUG_LOW("\t[-] Copying %lu bytes from section %s\n", section_header->SizeOfRawData, section_header->Name);
        memcpy((PBYTE) start_address + section_header->VirtualAddress,
               (PBYTE) dll_content + section_header->PointerToRawData, section_header->SizeOfRawData);
    }
    free(dll_parsed);

    // Return the DLL base address allocated
    return start_address;
}

/*
 * Process the memory mapped DLL relocations
 */
BOOL rebase(PE *dll_parsed) {
    // Parse relocations
    // https://0xrick.github.io/win-internals/pe8/#parsing-base-relocations
    // Relocation structure
    // --------------------------
    // | IMAGE_BASE_RELOCATION  |
    // | DWORD				    |
    // | DWORD				    |
    // --------------------------
    // | IMAGE_RELOCATION_ENTRY |
    // | DWORD                  |
    // | DWORD[3]				|
    // --------------------------
    // | IMAGE_RELOCATION_ENTRY |
    // | DWORD                  |
    // | DWORD[3]				|
    // --------------------------
    // | IMAGE_BASE_RELOCATION  |
    // | DWORD				    |
    // | DWORD				    |
    // --------------------------
    // | IMAGE_RELOCATION_ENTRY |
    // | DWORD                  |
    // | DWORD[3]				|
    // --------------------------

    DEBUG_LOW("[-] rebase: parsing relocations\n");
    SIZE_T number_of_relocations = 0;
    // Get the first relocation block
    IMAGE_BASE_RELOCATION *current_relocation = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (!dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress &&
        !dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        DEBUG_LOW("\t[+] rebase: no relocation to do !\n");
        return TRUE;
    }

    // Offset between the real DLL base address and the one expected
    // by the compiler when the DLL has been compiled
    // This offset will be added to each symbol address to relocate
    DWORD64 offset = (DWORD64) dll_parsed->baseAddress - (DWORD64) dll_parsed->ntHeader->OptionalHeader.ImageBase;

    // Iterate over each relocation block
    while (current_relocation->VirtualAddress) {
        DEBUG_LOW("\t[+] rebase: relocation processed : %X\n", current_relocation->VirtualAddress);
        // First block
        IMAGE_RELOCATION_ENTRY *relocation_entry = (PIMAGE_RELOCATION_ENTRY) &current_relocation[1];

        // Iterate over each relocation entry contained in the relocation block
        // See relocation structure in start of the function
        while ((DWORD64) relocation_entry < (DWORD64) current_relocation + current_relocation->SizeOfBlock) {
            // Compute the address of the symbol to relocate
            DWORD64 relocation_rva = current_relocation->VirtualAddress + relocation_entry->Offset;
            PVOID relocation_address = resolve_rva(dll_parsed, relocation_rva);

            if (relocation_entry->Type == IMAGE_REL_BASED_ABSOLUTE) {
                DEBUG_LOW("\t\t[-] rebase: relocation skipped as used for padding\n");
            } else if (relocation_entry->Type == IMAGE_REL_BASED_HIGHLOW) {
                if (offset > MAXDWORD) {
                    DEBUG_LOW("\t\t[x] rebase: relocation to long... Cannot process sry...");
                    return FALSE;
                }
                *((DWORD64 *) relocation_address) += (DWORD) offset;
            } else if (relocation_entry->Type == IMAGE_REL_BASED_DIR64) {
                *((DWORD64 *) relocation_address) += offset;
            } else {
                DEBUG_LOW("\t\t[x] rebase: relocation not supported sorry...\n");
                return FALSE;
            }

            DEBUG_LOW("\t\t[-] rebase: RVA : %llX\n", relocation_rva);
            DEBUG_LOW("\t\t[-] rebase: Offset : %d\n", relocation_entry->Offset);
            DEBUG_LOW("\t\t[-] rebase: Type : %d\n", relocation_entry->Type);
            DEBUG_LOW("\t\t[-] rebase: BaseOffset : 0x%llX\n", offset);
            DEBUG_LOW("\t\t[-] rebase: StartAddress : 0x%llX\n", (DWORD64) dll_parsed->baseAddress);
            DEBUG_LOW("\t\t[-] rebase: Reloc Address : 0x%p\n", relocation_address);
            DEBUG_LOW("\t\t[-] rebase: New value : 0x%llX\n", (*(DWORD64 *) relocation_address));

            // The next block is 0x08 bytes after, a ++ does the trick
            relocation_entry++;
            DEBUG_LOW("\n");
        }

        // Current relocation processed, go to the next one
        current_relocation = (PVOID) ((DWORD64) current_relocation + current_relocation->SizeOfBlock);
    }

    return TRUE;
}

/*
 * This function is used to hijack calls to ResolveDelayLoadedAPI
 * performed by the DLL to resolve address of function contained
 * in delayed loaded DLL.
 * Therefor, no need to load every delayed DLL when initially mapping
 * the DLL. This function will ensure that delayed DLL are loaded just
 * in time using the custom LoadLibrary procedure.
 */
PVOID WINAPI resolve_delay_loaded_api(PVOID parent_module_base, PCIMAGE_DELAYLOAD_DESCRIPTOR delayload_descriptor, PVOID failure_dll_hook, PVOID failure_system_hook, PIMAGE_THUNK_DATA thunk_address, ULONG flags) {
    HMODULE kernelbase = GetModuleHandleA("kernel32");
    // WORKSHOP TODO : Load the right function
    NT_DECL(ResolveDelayLoadedAPI) = (PVOID)GetProcAddress(kernelbase, "XXXXXX");

    // WORKSHOP TODO: Using IDA decompile the ResolveDelayLoadedAPI and find a way to compute the DLLName to load
    char *dllName = NULL;
    HMODULE dllHandle = GetModuleHandleA(dllName);
    if (!dllHandle) {
        DEBUG("[+] resolved_delay_loaded_api: delayed load for %s\n", dllName);
        dllHandle = LoadLibraryA(dllName);
    }
    return win32_ResolveDelayLoadedAPI(parent_module_base, delayload_descriptor, failure_dll_hook, failure_system_hook, thunk_address, flags);

    // This was the initial function that was used to resolved delayed
    // DLL and fill the IAT when the delayed load was done at the same
    // time that the standard import resolve.
    // I think it's better to directly use the ResolveDelayLoadedApi as
    // we don't have to manually reprotect the IAT table and it only costs
    // us a lookup in KERNELBASE. It should not be a problem as an IOC as
    // it is usually called from a random address in the DLL memory.

    /*
    IMAGE_DELAYLOAD_DESCRIPTOR* importDelayDescriptor = resolveRVA(dllParsed, dllParsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    PIMAGE_THUNK_DATA iat = (DWORD64)parent_module_base + importDelayDescriptor->ImportAddressTableRVA;
    PIMAGE_THUNK_DATA ilt = (DWORD64)parent_module_base + importDelayDescriptor->ImportNameTableRVA;

    for (; importDelayDescriptor->DllNameRVA; importDelayDescriptor++) {
        char* dllName = (char*)resolveRVA(dllParsed, importDelayDescriptor->DllNameRVA);
        DEBUG_LOW("\t[+] Descriptor name: %s\n", dllName);
        PIMAGE_THUNK_DATA iat = resolveRVA(dllParsed, importDelayDescriptor->ImportAddressTableRVA);
        PIMAGE_THUNK_DATA ilt = resolveRVA(dllParsed, importDelayDescriptor->ImportNameTableRVA);

        DEBUG_LOW("\t\t[-] IAT address : 0x%p\n", iat);
        if(dllName[0] == '\0'){
            continue;
        }
        HMODULE dllHandle = get_module_handle(hash_string(dllName, 0, NULL), NULL);
        if (!dllHandle) {
            DEBUG_LOW("\t\t[-] DLL not found, load the DLL\n");
        }

        for (; ilt->u1.Function; iat++, ilt++) {
            if (IMAGE_SNAP_BY_ORDINAL(ilt->u1.Ordinal)){
                LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(ilt->u1.Ordinal);
                iat->u1.Function = (DWORD_PTR)GetProcAddress(dllHandle, functionOrdinal);
                if(!iat->u1.Function){
                    DEBUG_LOW("[x] Failed to load function\n");
                    return FALSE;
                }
            }
            else {
                IMAGE_IMPORT_BY_NAME* hint = resolve_rva(dllParsed, ilt->u1.AddressOfData);
                DEBUG_LOW("\t\t[+] Function Name : %s\n", hint->Name);
                iat->u1.Function = (ULONGLONG)GetProcAddress(dllHandle, hint->Name);
                if(!iat->u1.Function){
                    DEBUG_LOW("[x] Failed to load function\n");
                    return FALSE;
                }
                DEBUG_LOW("\t\t[+] Function address : 0x%llX\n", iat->u1.Function);
                DEBUG_LOW("\n");
            }
        }
*/

}


/*
 * Resolve dependencies and fill the DLL IAT
 */
BOOL snapping(PE *dll_parsed) {
    DEBUG_LOW("[-] snapping: parsing imports\n");
    if (!dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress &&
        !dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        DEBUG_LOW("\t[x] snapping: no imports to process\n");
        return TRUE;
    }
    IMAGE_IMPORT_DESCRIPTOR *importDescriptor = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (SIZE_T i = 0; importDescriptor->Name; importDescriptor++) {
        char *dll_name = resolve_rva(dll_parsed, importDescriptor->Name);
        DEBUG_LOW("\t[+] snapping: descriptor name: %s\n", dll_name);
        PIMAGE_THUNK_DATA iat = resolve_rva(dll_parsed, importDescriptor->FirstThunk);
        PIMAGE_THUNK_DATA ilt = resolve_rva(dll_parsed, importDescriptor->OriginalFirstThunk);
        DEBUG_LOW("\t\t[-] snapping: IAT address : 0x%p\n", iat);
        if (dll_name[0] == '\0') {
            continue;
        }
        HMODULE dll_handle = GetModuleHandleA(dll_name);
        if (!dll_handle) {
            DEBUG_LOW("\t\t[-] DLL not found, load the DLL\n");
            dll_handle = LoadLibraryA(dll_name);
        }

        for (; ilt->u1.Function; iat++, ilt++) {
            if (IMAGE_SNAP_BY_ORDINAL(ilt->u1.Ordinal)) {
                int function_ordinal = IMAGE_ORDINAL(ilt->u1.Ordinal);
                iat->u1.Function = (DWORD_PTR)GetProcAddress(dll_handle, MAKEINTRESOURCE(function_ordinal));
            } else {
                IMAGE_IMPORT_BY_NAME *hint = resolve_rva(dll_parsed, ilt->u1.AddressOfData);
                // Hijack these functions to ensure that:
                // - every DLL loaded in the process will be loaded using the
                // custom loadlibrary function
                // - delayed functions resolve are redirected to our custom delay loading
                // function, otherwise it will load the DLL using the ntdll!LoadLibrary
                if (stricmp(hint->Name, "ResolveDelayLoadedAPI") == 0) {
                    // WORKSHOP TODO: Do the IAT hijacking !
                } else {
                    DEBUG_LOW("\t\t[+] snapping: function Name : %s\n", hint->Name);
                    iat->u1.Function = (DWORD_PTR) GetProcAddress(dll_handle, hint->Name);
                    DEBUG_LOW("\t\t[+] snapping: function address : 0x%llX\n", iat->u1.Function);
                    DEBUG_LOW("\n");
                }
            }
        }
    }
    return TRUE;
}

BOOL run_entrypoint(PE *dll_parsed) {

    // Time to re-protect all section according to their characteristics
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(dll_parsed->ntHeader);
    for (SIZE_T i = 0; i < dll_parsed->ntHeader->FileHeader.NumberOfSections; i++) {
        BOOL executable = (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL writable = (section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        BOOL readable = (section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;

        DWORD protection = 0;
        if (executable && writable && readable) { protection = PAGE_EXECUTE_READWRITE; }
        else if (executable && writable && !readable) { protection = PAGE_EXECUTE_WRITECOPY; }
        else if (executable && !writable && readable) { protection = PAGE_EXECUTE_READ; }
        else if (executable && !writable && !readable) { protection = PAGE_EXECUTE; }
        else if (!executable && writable && readable) { protection = PAGE_READWRITE; }
        else if (!executable && writable && !readable) { protection = PAGE_WRITECOPY; }
        else if (!executable && !writable && readable) { protection = PAGE_READONLY; }
        else if (!executable && !writable && readable) { protection = PAGE_NOACCESS; }
        DWORD old_protection;
        VirtualProtect(resolve_rva(dll_parsed, section_header->VirtualAddress), section_header->SizeOfRawData, protection, &old_protection);
        section_header++;
    }

    FlushInstructionCache((HANDLE) -1, NULL, 0);

    // Initialize TLS
    if (dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        PIMAGE_TLS_DIRECTORY pTlsDir = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK *ppCallback = (PIMAGE_TLS_CALLBACK *) (pTlsDir->AddressOfCallBacks);

        for (; *ppCallback; ppCallback++) {
            (*ppCallback)((PVOID) dll_parsed->baseAddress, DLL_PROCESS_ATTACH, NULL);
        }
    }

    // Register SEH exceptions
    if (dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        PIMAGE_RUNTIME_FUNCTION_ENTRY pFuncEntry = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        RtlAddFunctionTable(
                (PRUNTIME_FUNCTION) pFuncEntry,
                (dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1,
                (DWORD64) dll_parsed->baseAddress
        );
    }

    // Find the DLL entrypoint
    if (!dll_parsed->ntHeader->OptionalHeader.AddressOfEntryPoint) {
        // Some DLLs do not have entrypoint
        return TRUE;
    }

    LPDLLMAIN entryPoint = (LPDLLMAIN)resolve_rva(dll_parsed, dll_parsed->ntHeader->OptionalHeader.AddressOfEntryPoint);
    if (!entryPoint) {
        DEBUG_LOW("[-] run_entrypoint: cannot find entrypoint\n");
        return FALSE;
    } else {
        DEBUG_LOW("[+] run_entrypoint: found entrypoint at : 0x%p\n", entryPoint);
        // Run the entrypoint and retrieve the execution status
        SetLastError(0);
        BOOL status = entryPoint((DWORD_PTR) dll_parsed->baseAddress, DLL_PROCESS_ATTACH, NULL);
        DEBUG_MEDIUM("[+] run_entrypoint: entrypoint status : %d (%d)\n", status, GetLastError());
        return status;
    }
    return 1;
}


PVOID load_library_ex_a(LPCSTR filepath, HANDLE file, DWORD dwFlags){
    char cur = filepath[0];
    size_t size = 0;
    while (cur != '\0') {
        size += 1;
        cur = filepath[size];
    }
    size += 1;
    wchar_t filepath_w[MAX_PATH];
    for (int i = 0; i < size; i++) {
        filepath_w[i] = (wchar_t) filepath[i];
    }
    return load_library_ex_w(filepath_w, file, dwFlags);
}

PVOID load_library_a(LPSTR filepath) {
    return load_library_ex_a(filepath, NULL, 0);
}

PVOID load_library_w(LPWSTR filepath){
    return load_library_ex_w(filepath, NULL, 0);
}

PVOID load_library_ex_w(LPWSTR filepath, HANDLE file, DWORD dwFlags){
    return ldr_load_dll(filepath, file, dwFlags);
}


/*
 * Take a DLL name in UNICODE_STRING and return the hash value used to
 * register the DLL in the PEB hashtable
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
ULONG ldr_hash_entry(UNICODE_STRING UniName, BOOL xor_hash) {
    ULONG hash = 0;
    HMODULE ntdll = GetModuleHandle("NTDLL");
    NT_DECL(RtlHashUnicodeString) = (PVOID)GetProcAddress(ntdll, "RtlHashUnicodeString");

    win32_RtlHashUnicodeString(
            &UniName,
            TRUE,
            0,
            &hash
    );

    if (xor_hash) {
        hash &= (LDR_HASH_TABLE_ENTRIES - 1);
    }

    return hash;
}


BOOL add_mapping_info_module(PLDR_DATA_TABLE_ENTRY ldr_entry, PE *dll) {
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    NT_DECL(RtlRbInsertNodeEx) = (PVOID)GetProcAddress(ntdll, "RtlRbInsertNodeEx");
    PRTL_RB_TREE ldrp_module_mapping_info_index = (PRTL_RB_TREE) ((DWORD64) find_ldrp_module_mapping_info_index());

    if (!ldrp_module_mapping_info_index) {
        return FALSE;
    }
    BOOLEAN bRight = FALSE;
    PLDR_DATA_TABLE_ENTRY ldr_node = (PLDR_DATA_TABLE_ENTRY) ((size_t) ldrp_module_mapping_info_index->Root -
                                                              offsetof(LDR_DATA_TABLE_ENTRY, MappingInfoIndexNode));
    bRight = 0;
    BOOL bRight1 = 0;
    while (1) {
        if ((dll->ntHeader->FileHeader.TimeDateStamp <= ldr_node->TimeDateStamp) &&
            (dll->ntHeader->OptionalHeader.SizeOfImage < ldr_node->SizeOfImage)) {
            if (!ldr_node->MappingInfoIndexNode.Left) {
                break;
            }
            ldr_node = (PLDR_DATA_TABLE_ENTRY) ((DWORD64) (ldr_node->MappingInfoIndexNode.Left) -
                                                offsetof(LDR_DATA_TABLE_ENTRY, MappingInfoIndexNode));
        } else {
            if (!ldr_node->MappingInfoIndexNode.Right) {
                bRight1 = 1;
                break;
            }
            ldr_node = (PLDR_DATA_TABLE_ENTRY) ((DWORD64) (ldr_node->MappingInfoIndexNode.Right) -
                                                offsetof(LDR_DATA_TABLE_ENTRY, MappingInfoIndexNode));
        }
    }
    win32_RtlRbInsertNodeEx(
            ldrp_module_mapping_info_index,
            &ldr_node->MappingInfoIndexNode,
            bRight,
            &ldr_entry->MappingInfoIndexNode);

    return TRUE;
}


/*
 * Find the LdrpModuleMappingIndoIndexIndex variable in the NTDLL DLL
 */
PRTL_RB_TREE find_ldrp_module_mapping_info_index() {
    // Get the LDR_DATA_TABLE entry structure representing the
    // NTDLL loaded DLL. This DLL is used because we are sure
    // it is loaded. As KERNEL32 and KERNELBASE, NTDLL is one
    // of the three DLL that are always loaded in a process at
    // creation even if not used later by the process.
    PLDR_DATA_TABLE_ENTRY ldr_entry = get_ldr_entry(L"ntdll.dll");

    // Get a node in the red and black tree
    PRTL_BALANCED_NODE node = &ldr_entry->MappingInfoIndexNode;

    return rewind_tree(ldr_entry, node);
}

PLDR_DATA_TABLE_ENTRY get_ldr_entry(LPWSTR module_name){
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY hdr = NULL;
    PLIST_ENTRY ent = NULL;
    PLDR_DATA_TABLE_ENTRY ldr = NULL;
    hdr = &(peb->Ldr->InLoadOrderModuleList);
    ent = hdr->Flink;
    for (; hdr != ent; ent = ent->Flink){
        ldr = (void*)ent;
        if (wcsnicmp(ldr->BaseDllName.Buffer, module_name, ldr->BaseDllName.Length) == 0){
            return ldr;
        }
    }
    return NULL;
}


/*
 * Add the new loaded module in the LdrpModuleBaseAddressIndex tree
 * Highly (if not fully) inspired by the DarkLoadLibrary project by _batsec_
 */
BOOL add_base_address_entry(PLDR_DATA_TABLE_ENTRY ldr_entry, PE *dll) {
    HMODULE ntdll = GetModuleHandle("NTDLL");
    NT_DECL(RtlRbInsertNodeEx) = (PVOID)GetProcAddress(ntdll, "RtlRbInsertNodeEx");

    PRTL_RB_TREE ldrp_module_base_address_index = NULL;
    BOOL right_leaf = FALSE;
    PLDR_DATA_TABLE_ENTRY ldr_node = NULL;

    insert_module_base_address_node(dll->baseAddress, &ldrp_module_base_address_index, &ldr_node, &right_leaf);
    if(!ldrp_module_base_address_index || !ldr_node){
        return FALSE;
    }
    // Finally, just insert the node in the tree
    win32_RtlRbInsertNodeEx(ldrp_module_base_address_index, &ldr_node->BaseAddressIndexNode, right_leaf,
                            &ldr_entry->BaseAddressIndexNode);

    // Don't really know the interest of this, but it is in the DLL
    // and does not impact the loader functioning.
    ldr_entry->Flags |= 0x80;
    return TRUE;
}

/*
 * This function is used to either update the load count of an
 * already loaded DLL or retrieve the ldrp_module_base_address_index
 * and the parent node in the red and black tree
 */
BOOL insert_module_base_address_node(PVOID base_address, PRTL_RB_TREE *module_base_address_index,
                                     PLDR_DATA_TABLE_ENTRY *node, BOOL *right_leaf) {
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    NT_DECL(RtlRbInsertNodeEx) = (PVOID)GetProcAddress(ntdll, "RtlRbInsertNodeEx");

    // Get the LdrpModuleBaseAddressIndex
    PRTL_RB_TREE ldrp_module_base_address_index = find_ldrp_module_base_address_index();
    if(module_base_address_index){
        *module_base_address_index = ldrp_module_base_address_index;
    }
    if (!ldrp_module_base_address_index) {
        return FALSE;
    }

    if(right_leaf) *right_leaf = FALSE;
    // The ldr_node is embedded as is in the LDR_DATA_TABLE_ENTRY structure.
    // It is possible to jump from the tree node to the LDR_DATA_TABLE_ENTRY
    // by subtracting the offset of the BaseAddressIndexNode element in the
    // LDR_DATA_TABLE_ENTRY to the node current address.
    PLDR_DATA_TABLE_ENTRY ldr_node = (PLDR_DATA_TABLE_ENTRY) ((size_t) ldrp_module_base_address_index->Root -
                                                              offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));

    // This loop is used to insert the node at the right place
    // in the tree using standard black and red tree insertion
    // algorithm.
    // This tree is sorted by module base address.
    do {
        if (base_address < ldr_node->DllBase) {
            if (!ldr_node->BaseAddressIndexNode.Left) {
                if(node) *node = ldr_node;
                return FALSE;
            }
            // Each time we get back the LDR_DATA_TABLE_ENTRY from the node
            // It is easier to extract data from this structure to find the
            // right tree leaf where the node will be inserted.
            ldr_node = (PLDR_DATA_TABLE_ENTRY) ((size_t) ldr_node->BaseAddressIndexNode.Left -
                                                offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));
        }
            // Same as previous block but for the right branch
            // instead of the left
        else if (base_address > ldr_node->DllBase) {
            if (!ldr_node->BaseAddressIndexNode.Right) {
                if(right_leaf) *right_leaf = TRUE;
                if(node) *node = ldr_node;
                return FALSE;
            }
            ldr_node = (PLDR_DATA_TABLE_ENTRY) ((size_t) ldr_node->BaseAddressIndexNode.Right -
                                                offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));
        } else {
            // The DLL has already been inserted in the list, so that means
            // the DLL is already loaded taken into account in the process.
            // The DdagNode is a dependency node used by the Windows dependency
            // graph that is used to reduce dependencies conflict when doing
            // parallel loading.
            if(ldr_node->DdagNode->LoadCount != -1){
                ldr_node->DdagNode->LoadCount++;
            }
            return TRUE;
        }
    } while (TRUE);
}

/*
 * Find the LdrpModuleBaseAddressIndex variable in the NTDLL DLL
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
PRTL_RB_TREE find_ldrp_module_base_address_index() {
    // Get the LDR_DATA_TABLE entry structure representing the
    // NTDLL loaded DLL. This DLL is used because we are sure
    // it is loaded. As KERNEL32 and KERNELBASE, NTDLL is one
    // of the three DLL that are always loaded in a process at
    // creation even if not used later by the process.
    PLDR_DATA_TABLE_ENTRY ldr_entry = get_ldr_entry(L"ntdll.dll");

    // Get a node in the red and black tree
    PRTL_BALANCED_NODE node = &ldr_entry->BaseAddressIndexNode;
    return rewind_tree(ldr_entry, node);
}

/*
 * This function is used to rewind the red and black treee to get the
 * root node.
 * This is mainly used in the find_ldrp_module_mapping_info_index and
 * the find_ldrp_module_base_address_index to retrieve the
 * LdrpModuleMappingInfoIndex and the LdrpModuleBaseAddressIndex value
 *
 * Highly inspired from the _batsec_ DarkLoadLibrary project
 */
PRTL_RB_TREE rewind_tree(PLDR_DATA_TABLE_ENTRY ldr_entry, PRTL_BALANCED_NODE node){
    SIZE_T section_end = 0;
    // Rewind the red and black tree until finding the
    // root node
    while (node->ParentValue & (~7)){
        node = (PRTL_BALANCED_NODE) (node->ParentValue & (~7));
    }

    // The root node is always black in a red
    // and black tree
    if (!node->Red) {
        DWORD section_size = 0;
        SIZE_T section_address = 0;

        // Now we got the tree root node, lets find the LdrpModuleBaseAddressIndex
        // value in memory by locating reference to the root node address

        // The value is stored in the .data section, so lets get
        // the .data section address
        PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS) ((DWORD64) ldr_entry->DllBase +
                                                            ((PIMAGE_DOS_HEADER) ldr_entry->DllBase)->e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            if (strncmp((char*)section->Name, ".data", 5) == 0) {
                section_address = (SIZE_T) ldr_entry->DllBase + section->VirtualAddress;
                section_size = section->Misc.VirtualSize;
                break;
            }
            ++section;
        }

        // Let's parse the .data section until the reference to the node is
        // found
        for (DWORD i = 0; i < section_size - sizeof(SIZE_T); ++section_address, ++i) {
            if(*(SIZE_T*)section_address == *(SIZE_T*)&node){
                // If the current address contains the node value then we
                // found it
                section_end = section_address;
                break;
            }
        }

        // The whole .data section has been searched and
        // nothing was found.
        // Captain, we failed...
        if (section_end == 0) {
            return NULL;
        }

        // This is the LdrpModuleBaseAddressIndex
        PRTL_RB_TREE tree = (PRTL_RB_TREE) section_end;

        if (tree && tree->Root && tree->Min) {
            return tree;
        }
    }
    return NULL;
}


/*
 * Global function that link a given DLL to the PEB
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
PVOID link_module_to_peb(PE *dll, LPWSTR DllPath, LPWSTR DllName) {
    PIMAGE_NT_HEADERS nt_headers;
    UNICODE_STRING full_dll_name, base_dll_name;
    PLDR_DATA_TABLE_ENTRY ldr_entry = NULL;
    HMODULE ntdll = GetModuleHandle("NTDLL");
    NT_DECL(RtlInitUnicodeString) = (PVOID)GetProcAddress(ntdll, "RtlInitUnicodeString");
    NT_DECL(NtQuerySystemTime) = (PVOID)GetProcAddress(ntdll, "NtQuerySystemTime");
    nt_headers = dll->ntHeader;

    // convert the names to unicode
    win32_RtlInitUnicodeString(&full_dll_name, DllPath);

    win32_RtlInitUnicodeString(&base_dll_name, DllName);

    // link the entry to the PEB
    ldr_entry = (PLDR_DATA_TABLE_ENTRY)calloc(1, sizeof(LDR_DATA_TABLE_ENTRY));

    if (!ldr_entry) { return NULL; }

    // start setting the values in the entry
    win32_NtQuerySystemTime(&ldr_entry->LoadTime);

    // do the obvious ones
    ldr_entry->ReferenceCount = 1;
    ldr_entry->LoadReason = LoadReasonDynamicLoad;
    ldr_entry->OriginalBase = nt_headers->OptionalHeader.ImageBase;

    // set the hash value
    ldr_entry->BaseNameHashValue = ldr_hash_entry(base_dll_name, FALSE);
    // correctly add the base address to the entry
    add_mapping_info_module(ldr_entry, dll);
    add_base_address_entry(ldr_entry, dll);

    // and the rest
    ldr_entry->ImageDll = TRUE;
    ldr_entry->LoadNotificationsSent = TRUE;
    ldr_entry->EntryProcessed = TRUE;
    ldr_entry->InLegacyLists = TRUE;
    ldr_entry->InIndexes = TRUE;
    ldr_entry->ProcessAttachCalled = TRUE;
    ldr_entry->InExceptionTable = TRUE;
    ldr_entry->DllBase = dll->baseAddress;
    ldr_entry->SizeOfImage = nt_headers->OptionalHeader.SizeOfImage;
    ldr_entry->TimeDateStamp = nt_headers->FileHeader.TimeDateStamp;
    ldr_entry->BaseDllName = base_dll_name;
    ldr_entry->FullDllName = full_dll_name;
    ldr_entry->ObsoleteLoadCount = 1;
    ldr_entry->Flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;

    // set the correct values in the Ddag node struct
    ldr_entry->DdagNode = calloc(1, sizeof(LDR_DDAG_NODE));
    if (!ldr_entry->DdagNode) { return 0; }

    ldr_entry->NodeModuleLink.Flink = &ldr_entry->DdagNode->Modules;
    ldr_entry->NodeModuleLink.Blink = &ldr_entry->DdagNode->Modules;
    ldr_entry->DdagNode->Modules.Flink = &ldr_entry->NodeModuleLink;
    ldr_entry->DdagNode->Modules.Blink = &ldr_entry->NodeModuleLink;
    ldr_entry->DdagNode->State = LdrModulesReadyToRun;
    ldr_entry->DdagNode->LoadCount = 1;

    // add the hash to the LdrpHashTable
    add_hash_table_entry(ldr_entry);

    // set the entry point
    ldr_entry->EntryPoint = resolve_rva(dll, nt_headers->OptionalHeader.AddressOfEntryPoint);

    return ldr_entry;
}

/*
 * Add a new entry in the hashtable
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
BOOL add_hash_table_entry(PLDR_DATA_TABLE_ENTRY ldr_entry) {
    PPEB peb = GetPEB();

    // Initialize the new entry
    InitializeListEntry(&ldr_entry->HashLinks);

    // Retrieve the hashtable
    PLIST_ENTRY ldrp_hash_table = find_hash_table();
    if (!ldrp_hash_table) {
        return FALSE;
    }

    // Insert the entry in the hashtable
    ULONG ulHash = ldr_hash_entry(ldr_entry->BaseDllName, TRUE);
    insert_tail_list(&ldrp_hash_table[ulHash], &ldr_entry->HashLinks);
    insert_tail_list(&peb->Ldr->InLoadOrderModuleList, &ldr_entry->InLoadOrderLinks);
    insert_tail_list(&peb->Ldr->InMemoryOrderModuleList, &ldr_entry->InMemoryOrderLinks);
    insert_tail_list(&peb->Ldr->InInitializationOrderModuleList, &ldr_entry->InInitializationOrderLinks);
    return TRUE;
}

/*
 * Simple helper that add element to the tail of a
 * list
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
VOID insert_tail_list(PLIST_ENTRY list_head, PLIST_ENTRY entry) {
    PLIST_ENTRY blink = list_head->Blink;
    entry->Flink = list_head;
    entry->Blink = blink;
    blink->Flink = entry;
    list_head->Blink = entry;
}

/*
 * Locate the hashtable by using the HashLink stored in the PEB
 * The HashLink list is rewind until finding the first hashtable
 * element.
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
PLIST_ENTRY find_hash_table() {
    PLIST_ENTRY list = NULL;
    PLDR_DATA_TABLE_ENTRY current_entry = NULL;

    PPEB peb = GetPEB();
    PLIST_ENTRY head = &peb->Ldr->InInitializationOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    do {
        current_entry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
        entry = entry->Flink;
        if (current_entry->HashLinks.Flink == &current_entry->HashLinks) {
            continue;
        }

        list = current_entry->HashLinks.Flink;

        if (list->Flink == &current_entry->HashLinks) {
            ULONG ul_hash = ldr_hash_entry(current_entry->BaseDllName, TRUE);
            list = (PLIST_ENTRY) ((size_t) current_entry->HashLinks.Flink - ul_hash * sizeof(LIST_ENTRY));
            break;
        }
        list = NULL;
    } while (head != entry);

    return list;
}

void resolve_dll_path(LPWSTR initial_dll_name, LPWSTR *dll_name, DWORD *dll_name_size, LPWSTR *dll_path, DWORD *dll_path_size) {
    wchar_t resolved_api[MAX_PATH];
    wchar_t extension[5] = {L'.', L'd', L'l', L'l', L'\0'};
    int i = 0;
    int last_dot = -1;
    while(initial_dll_name[i] != '\0') {
        if (initial_dll_name[i] == L'.') {
            last_dot = i;
        }
        resolved_api[i] = initial_dll_name[i];
        i += 1;
    }
    if(last_dot == -1){
        resolved_api[i] = L'\0';
    }
    else {
        resolved_api[last_dot] = L'\0';
    }

    *dll_path = calloc(MAX_PATH, sizeof(wchar_t));
    *dll_path_size = SearchPathW(NULL, resolved_api, extension, MAX_PATH, *dll_path, NULL);

    if (!*dll_path_size) {
        DEBUG_MEDIUM("[x] resolve_dll_path: failed to get DLL path %ls (%ls)\n", resolved_api, initial_dll_name);
        return;
    }

    DEBUG_MEDIUM("[+] resolve_dll_path: dll %ls resolve into %ls\n", initial_dll_name, resolved_api);
    int last = 0;
    for (unsigned int i = 0; i < *dll_path_size; i++) {
        if ((*dll_path)[i] == L'\\') {
            last = i + 1;
        }
    }
    *dll_name = &((*dll_path)[last]);
    *dll_name_size = *dll_path_size - last;
}



/*
 * Search for the LdrpInvertedFunctionTable in the NTDLL memory
 */
PVOID search_for_ldrp_inverted_function_table(PVOID *mr_data, PULONG mr_data_size) {
    PVOID ldrp_inverted_function_table = NULL;
    // Get address of the NTDLL DLL
    PVOID ntdll = GetModuleHandleA("ntdll.dll");

    // Parse the loaded DLL into a PE structure. Not mandatory but
    // ease the retrieval of specific data
    PE *pe = pe_create(ntdll, TRUE);

    // The LdrpInvertedFunctionTable is stored in the .mrdata
    // Enumerate all sections until the .mrdata is found
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(pe->ntHeader);
    *mr_data = NULL;
    for (DWORD i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++, section_header++) {
        if (strcmp((char *) section_header->Name, ".mrdata") == 0) {
            *mr_data = (PBYTE) ntdll + section_header->VirtualAddress;
            *mr_data_size = (DWORD64) section_header->SizeOfRawData;
            break;
        }
    }
    free(pe);
    if (!*mr_data) {
        DEBUG_MEDIUM("[x] search_for_ldrp_inverted_function_table: failed to find .mrdata section\n");
        return NULL;
    }

    // We parse the .mr_data section until we found something that look like
    // the LdrpInvertedFunctionTable
    PVOID candidate = *mr_data;
    while ((DWORD64) candidate <= (DWORD64) *mr_data + *mr_data_size - sizeof(RTL_INVERTED_FUNCTION_TABLE)) {
        RTL_INVERTED_FUNCTION_TABLE *ldr_table = candidate;

        // We know some restriction on the LdrpInvertedFunctionTable
        // It represents a structure containing the Count and MaxCount
        // element.
        // The MaxCount is always lower than 512, the Count always more
        // than 0 (as at least the NTDLL, KERNEL32 and KERNELBASE are
        // already loaded)
        if (
                ldr_table->Count > 0 &&
                ldr_table->MaxCount > 0 &&
                ldr_table->MaxCount <= 512 &&
                ldr_table->Count <= ldr_table->MaxCount
                ) {
            int valid = 1;
            // This is a serious candidate, but let go deeper in the investigation
            // All element in the LdrpInvertedFunctionTable are structure containing
            // easy to verify information : the DLL base address, size, the exception
            // directory address and size.
            // So for each element in the table, let's see if all value matches
            for (unsigned int i = 0; i < ldr_table->Count; i++) {

                // Check if the export directory is in the DLL memory using
                // the DLL base address and size
                if(!ldr_table->Entries[i].ExceptionDirectory){
                    continue;
                }
                if (
                        (ldr_table->Entries[i].ExceptionDirectory) && (
                                (PVOID) ldr_table->Entries[i].ExceptionDirectory < ldr_table->Entries[i].ImageBase ||
                                (DWORD64) ldr_table->Entries[i].ExceptionDirectory >=
                                (DWORD64) ldr_table->Entries[i].ImageBase + ldr_table->Entries[i].ImageSize)
                        ) {
                    // It does not match, let's go to next candidate
                    valid = 0;
                    break;
                } else {
                    // Export directory is in the DLL memory range but let's check that
                    // the export directory address retrieved is coherent with the one
                    // computed directly from the DLL base address
                    PE *candidate_pe = pe_create(ldr_table->Entries[i].ImageBase, TRUE);
                    if (!candidate_pe) {
                        DEBUG_MEDIUM("[x] search_for_ldrp_inverted_function_table: failed to create pe structure\n");
                        continue;
                    }
                    if (
                            resolve_rva(candidate_pe, candidate_pe->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress) !=
                            ldr_table->Entries[i].ExceptionDirectory ||
                            candidate_pe->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size !=
                            ldr_table->Entries[i].ExceptionDirectorySize ||
                            candidate_pe->optionalHeader->SizeOfImage != ldr_table->Entries[i].ImageSize
                            ) {
                        // The export directory address is not coherent with the one computed manually
                        // from the DLL base. It's a false positive, let's go to the next candidate.
                        valid = 0;
                        free(candidate_pe);
                        break;
                    }
                    free(candidate_pe);
                }
            }
            if (valid) {
                // All checks passed, this should be the LdrpInvertedFunctionTable
                DEBUG_MEDIUM("[+] search_for_ldrp_inverted_function_table: found candidate : 0x%p\n", candidate);
                return candidate;
            }
        }
        // Go to the next candidate
        candidate = (PVOID) ((DWORD64)candidate + sizeof(char));

    }
    return NULL;
}

/*
 * Insert element in the RtlpInsertInvertedFunctionTable
 */
void rtlp_insert_inverted_function_table_entry(PVOID image_base, ULONG image_size, PVOID exception_directory,
                                               ULONG exception_directory_size) {
    PVOID mr_data;
    ULONG mr_data_size;

    // Get the RtlpInsertInvertedFunctionTable element
    RTL_INVERTED_FUNCTION_TABLE *ldrp_inverted_function_table = search_for_ldrp_inverted_function_table(
            &mr_data,
            &mr_data_size);
    if (!ldrp_inverted_function_table) {
        DEBUG_MEDIUM("[x] rtlp_insert_inverted_function_table_entry: failed to get the inverted function table\n");
        return;
    }
    DWORD old_protect;

    // The table is in the .mrdata section that is readonly
    // re-protect the section in read write. This sections is
    // made to see its protection changed from ro to rw
    if (!VirtualProtect(mr_data, mr_data_size, PAGE_READWRITE, &old_protect)) {
        DEBUG_MEDIUM("[x] rtlp_insert_inverted_function_table_entry: failed to reprotect .mrdata section\n");
        return;
    }

    ULONG table_count = ldrp_inverted_function_table->Count;
    ULONG entry_index = 0;
    // If the table is full, let update the pad
    // No idea how it is used later, but it is like this in the
    // NTDLL
    if (ldrp_inverted_function_table->Count == ldrp_inverted_function_table->MaxCount) {
        ldrp_inverted_function_table->Pad[1] = 1;
    } else {
        // Atomic increment
        (*ldrp_inverted_function_table->Pad) += 1;
        entry_index = 1;
        if (ldrp_inverted_function_table->Count != 1) {
            // The table is sorted by base address
            // Look for the index where the new element must be inserted
            while (entry_index < ldrp_inverted_function_table->Count) {
                if (image_base < ldrp_inverted_function_table->Entries[entry_index].ImageBase) {
                    break;
                }
                entry_index += 1;
            }
        }
        // Shift the next element to get a space where the
        // new element can be inserted
        if (entry_index != ldrp_inverted_function_table->Count) {
            memmove(
                    &ldrp_inverted_function_table->Entries[entry_index + 1],
                    &ldrp_inverted_function_table->Entries[entry_index],
                    (ldrp_inverted_function_table->Count - entry_index) * sizeof(RTL_INVERTED_FUNCTION_TABLE_ENTRY)
            );
        }
    }
    // Let's write the new element in the table
    ldrp_inverted_function_table->Entries[entry_index].ImageBase = image_base;
    ldrp_inverted_function_table->Entries[entry_index].ImageSize = image_size;
    ldrp_inverted_function_table->Entries[entry_index].ExceptionDirectory = exception_directory;
    ldrp_inverted_function_table->Entries[entry_index].ExceptionDirectorySize = exception_directory_size;
    ldrp_inverted_function_table->Count += 1;

    // Atomic increment
    (*ldrp_inverted_function_table->Pad) += 1;

    // Don't forget to re-protect the section once the
    // element has been inserted
    VirtualProtect(mr_data, mr_data_size, old_protect, &old_protect);
}




PVOID ldr_load_dll(LPWSTR filepath, HANDLE file, DWORD dwFlags){
    LPWSTR dll_name = NULL;
    LPWSTR dll_path = NULL;
    DWORD dll_path_size = 0;
    DWORD dll_name_size = 0;

    resolve_dll_path(filepath, &dll_name, &dll_name_size, &dll_path, &dll_path_size);
    if(dll_path_size == 0){
        DEBUG_MEDIUM("[x] ldr_load_dll: failed to load the %ls DLL\n", filepath);
        return NULL;
    }

    PVOID startAddress = minimal_memory_map(dll_path);
    if (!startAddress) {
        return NULL;
    }
    PE *dll_parsed = pe_create(startAddress, TRUE);
    PLDR_DATA_TABLE_ENTRY pLdrEntry = link_module_to_peb(dll_parsed, dll_path, dll_name);
    if (!dll_parsed) {
        return NULL;
    }
    if (!rebase(dll_parsed)) {
        free(dll_parsed);
        return NULL;
    }

    rtlp_insert_inverted_function_table_entry(
            startAddress,
            dll_parsed->optionalHeader->SizeOfImage,
            resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
            dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);

    if (!snapping(dll_parsed)) {
        free(dll_parsed);
        return NULL;
    }
    DEBUG_MEDIUM("[+] ldr_load_dll: executing entrypoint for %ls\n", dll_name);
    if (!run_entrypoint(dll_parsed)) {
        free(dll_parsed);
        return NULL;
    }

    DEBUG_MEDIUM("[+] ldr_load_dll: dll %ls is loaded\n", dll_name);
    free(dll_parsed);
    return startAddress;
}
