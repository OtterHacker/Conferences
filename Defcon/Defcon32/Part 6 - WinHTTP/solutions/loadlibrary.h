#ifndef AZRAEL_IMPLANT_LOADLIBRARY_H
#define AZRAEL_IMPLANT_LOADLIBRARY_H
#include <stdlib.h>
#include <stdio.h>
#include "winapi.h"


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
 * Search for the LdrpInvertedFunctionTable in the NTDLL memory
 */
PVOID search_for_ldrp_inverted_function_table(PVOID *mr_data, PULONG mr_data_size);

/*
 * Insert element in the RtlpInsertInvertedFunctionTable
 */
void rtlp_insert_inverted_function_table_entry(PVOID image_base, ULONG image_size, PVOID exception_directory, ULONG exception_directory_size);

/*
 * This function is used to hijack calls to ResolveDelayLoadedAPI
 * performed by the DLL to resolve address of function contained
 * in delayed loaded DLL.
 * Therefor, no need to load every delayed DLL when initially mapping
 * the DLL. This function will ensure that delayed DLL are loaded just
 * in time using the custom LoadLibrary procedure.
 */
PVOID resolve_delay_loaded_api(PVOID parent_module_base, PCIMAGE_DELAYLOAD_DESCRIPTOR delayload_descriptor, PVOID failure_dll_hook, PVOID failure_system_hook, PIMAGE_THUNK_DATA thunk_address, ULONG flags);

/*
 * Cannot explain deeply how work all the api_setp function I
 * just recopied what was done in the NTDLL but basically, to ease
 * portability among devices (PC, Xbox, Tablet) Microsoft started
 * using API Set that ensure that a given set of function will be
 * loaded even if they are in fact exported by totally different DLL.
 *
 * ApiSet are ended by .dll but they are not DLL. They can be seen
 * as pointer to other DLL whose value can change from on techno
 * to another
 *
 * For example, that you are on Xbox or PC, the following APISet
 * api-ms-win-core-processthreads-l1-1-0.dll will always load the
 * same set of functions whereas they are stored in NTDLL for PC
 * and U_MOM.DLL in Xbox
 *
 * The api_setp_* set of function are used to resolve the DLL name
 * from the ApiSet name. This can be done cause when the process is
 * created, Windows stores the mapping in the PEB under the APISetMap
 * attribute.
 */

/*
 * This function take an api namespace and an api to resolve and retrieve
 * the entry in the Api Namespace that contains the DLL related to the
 * Api Set to resolve
 */
API_SET_NAMESPACE_ENTRY *api_setp_search_for_api_set(API_SET_NAMESPACE *api_namespace, wchar_t *api_to_resolve, SHORT api_to_resolve_size);

/*
 * I'm not really sure for this one, but it seems to be used
 * to avoid infinite loop when a DLL is using as a forwarder
 * an ApiSet that resolve on itself.
 * For example, the KERNEL32!DeleteProcThreadAttributeList
 * function is forwarded to the ApiSet api-ms-win-core-processthreads-l1-1-0.dll
 * that resolves to KERNEL32 leading to an infinite loop
 * When this function is used, the resolution of the ApiSet when
 * asked by a forwarder will end in KERNELBASE instead of K32.
 *
 * Otherwise, I don't have any clue how all of it works internally
 * but it seems that this edge case is taken into account in the
 * ApiSetMap definition.
 */
API_SET_VALUE_ENTRY * api_setp_search_for_api_set_host(API_SET_NAMESPACE_ENTRY *api_namespace_entry, wchar_t *api_to_resolve, unsigned __int16 api_to_resolve_size, API_SET_NAMESPACE *api_namespace);

/*
 * Given an Api Namespace and a ApiSet to resolve, it finds
 * the DLL related to the ApiSet
 */
NTSTATUS api_set_resolve_host(API_SET_NAMESPACE *api_namespace, PUNICODE_STRING api_to_resolve, PUNICODE_STRING parent_name, int *resolved, PUNICODE_STRING resolved_dll);

/*
 * High level function that given an ApiSet, return the related
 * DLL
 */
int resolve_api_set(PWSTR api_set, PWSTR resolved_api, PWSTR parent);

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

void resolve_dll_path(LPWSTR initial_dll_name, LPWSTR *dll_name, DWORD *dll_name_size, LPWSTR *dll_path, DWORD *dll_path_size);
PVOID load_library_ex_a(LPCSTR dllName, HANDLE file, DWORD dwFlags);
PVOID load_library_ex_w(LPWSTR dllName, HANDLE file, DWORD dwFlags);
PVOID load_library_w(LPWSTR filepath);
PVOID load_library_a(LPSTR filepath);
BOOL free_library(HANDLE library);
PVOID ldr_load_dll(LPWSTR filepath, HANDLE file, DWORD dwFlags);
#endif //AZRAEL_IMPLANT_LOADLIBRARY_H
