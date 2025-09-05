#ifndef AZRAEL_IMPLANT_LOADLIBRARY_H
#define AZRAEL_IMPLANT_LOADLIBRARY_H
#include <stdlib.h>
#include <stdio.h>
#include "winapi.h"


typedef BOOL(WINAPI* LPDLLMAIN)(DWORD_PTR image_base, DWORD reason, LPVOID reserved);
PBYTE read_file_w(LPWSTR filename, PDWORD file_size);

/*
 * Helper that given a base address will map the element
 * in a structure representing the PE.
 */
PE *pe_create(PVOID image_base, BOOL is_memory_mapped);
PVOID resolve_rva(PE* pe, DWORD64 rva);

/*
 * Read the DLL file to load and map the section in memory
 */
PVOID minimal_memory_map(LPWSTR filepath);

/*
 * Process the memory mapped DLL relocations
 */
BOOL rebase(PE *dll_parsed);

/*
 * Resolve dependencies and fill the DLL IAT
 */
BOOL snapping(PE *dll_parsed);

/*
 * Set the protection on the DLL sections and run the entrypoint
 */
BOOL run_entrypoint(PE *dll_parsed);

PVOID load_library_ex_a(LPCSTR dllName, HANDLE file, DWORD dwFlags);
PVOID load_library_ex_w(LPWSTR dllName, HANDLE file, DWORD dwFlags);
PVOID load_library_w(LPWSTR filepath);
PVOID load_library_a(LPSTR filepath);
PVOID ldr_load_dll(LPWSTR filepath, HANDLE file, DWORD dwFlags);
void resolve_dll_path(LPWSTR initial_dll_name, LPWSTR *dll_name, DWORD *dll_name_size, LPWSTR *dll_path, DWORD *dll_path_size);




/************************************************************/
/*                      NEW FUNCTIONS                       */
/************************************************************/
/*
 * Take a DLL name in UNICODE_STRING and return the hash value used to
 * register the DLL in the PEB hashtable
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
ULONG ldr_hash_entry(UNICODE_STRING UniName, BOOL xor_hash);

/*
 * Locate the hashtable by using the HashLink stored in the PEB
 * The HashLink list is rewind until finding the first hashtable
 * element.
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
PLIST_ENTRY find_hash_table();

/*
 * Simple helper that add element to the tail of a
 * list
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
VOID insert_tail_list(PLIST_ENTRY list_head, PLIST_ENTRY entry);

/*
 * Add a new entry in the hashtable
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
BOOL add_hash_table_entry(PLDR_DATA_TABLE_ENTRY ldr_entry);

/*
 * Find the LdrpModuleBaseAddressIndex variable in the NTDLL DLL
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
PRTL_RB_TREE find_ldrp_module_base_address_index();

/*
 * Add the new loaded module in the LdrpModuleBaseAddressIndex tree
 * Highly (if not fully) inspired by the DarkLoadLibrary project by _batsec_
 */
BOOL add_base_address_entry(PLDR_DATA_TABLE_ENTRY ldr_entry, PE *dll);

/*
 * Global function that link a given DLL to the PEB
 * Fully stolen to the DarkLoadLibrary project by _batsec_
 */
PVOID link_module_to_peb(PE *dll, LPWSTR DllPath, LPWSTR DllName);

/*
 * Find the LdrpModuleMappingIndoIndexIndex variable in the NTDLL DLL
 */
PRTL_RB_TREE find_ldrp_module_mapping_info_index();

/*
 * This function is used to rewind the red and black treee to get the
 * root node.
 * This is mainly used in the find_ldrp_module_mapping_info_index and
 * the find_ldrp_module_base_address_index to retrieve the
 * LdrpModuleMappingInfoIndex and the LdrpModuleBaseAddressIndex value
 *
 * Highly inspired from the _batsec_ DarkLoadLibrary project
 */
PRTL_RB_TREE rewind_tree(PLDR_DATA_TABLE_ENTRY ldr_entry, PRTL_BALANCED_NODE node);

/*
 * This function is used to either update the load count of an
 * already loaded DLL or retrieve the ldrp_module_base_address_index
 * and the parent node in the red and black tree
 */
BOOL insert_module_base_address_node(PVOID base_address, PRTL_RB_TREE *module_base_address_index, PLDR_DATA_TABLE_ENTRY *node, BOOL *right_leaf);

/*
 * Retrieve the LDR entry using the PEB module linked list
 * This is also usefull for a custom GetModuleHandle and
 * GetProcAddress
 */
PLDR_DATA_TABLE_ENTRY get_ldr_entry(LPWSTR module_name);


#endif //AZRAEL_IMPLANT_LOADLIBRARY_H
