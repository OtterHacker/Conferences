# Part 1 - AMSI

# Main objectives
The main objective of this activity is to play with DLL and C. 

## Basic behavior
First tasks:

- Loading a DLL using LoadLibrary
- Using Procmon, looking at the different event raised during the DLL loading
- Using WinDbg, finding which function of the NTDLL is raising such events

## The first loader
- Implementing the different steps to load a DLL in memory
- Using Procmon, looking at the different events raised during the DLL
- Trying to use the Win32 API functions with the loaded DLL

# Steps
## Load a library in C
The first step is to load a DLL a DLL using LoadLibrary.

On the `main.c` file, replace the line:
```c
HMODULE amsi = load_library_a("C:\\Windows\\System32\\amsi.dll");
```

by

```c
HMODULE amsi = LoadLibraryA("C:\\Windows\\System32\\amsi.dll");
```

Compile the project and run it. You should have the following result:

```bash
[+] AmsiInitialize address : 0x00007FFF2BD634E0
[+] AMSI Initialize succeed !
```

## Analyze the events
In the `main.c` add a `getchar()` before running the `LoadLibraryA`:

```c
[...]

getchar();
HMODULE amsi = LoadLibraryA("C:\\Windows\\System32\\amsi.dll");

[...]
```

Open Procmon and run the program. Look at the different DLL loaded during the process startup.

Then, press any key on the `LoadLibrary.exe` console to resume the program and look at the events raised by `LoadLibraryA`

## Custom library loading
Remove all the changes you've made on the `main` function.

Your goal is to manually load the DLL without using the LoadLibrary function or any related function.

For that, you have to modify the `ldr_load_dll` function located in 'loadlibrary.c` file.

All the functions you need are documented in the `loadlibrary.h` file.

According to the theoretical course, set the following functions in the good order :

```c
BOOL rebase(PE *dll_parsed);
PVOID minimal_memory_map(LPWSTR filepath);
BOOL run_entrypoint(PE *dll_parsed);
BOOL snapping(PE *dll_parsed);
```

Some of these functions will not work right away. You have to fix them. Look for the `// WORKSHOP TODO` comments to locate the part of the code that must be fixed.

## Analyze the events
With procmon look at the events raised during the custom library loading.

What do you see ?

## Win32 API
Try using the `GetProcAddress` instead of the `get_proc_address_c`.

Is it still working ? Why ?

Try finding the root cause by reversing the GetProcAddress function and digging into the NTDLL. You should find how the DLL is integrated to the PEB. Try to identify the adhesions between the DLL and the PEB.