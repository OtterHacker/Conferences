# Traumatic Library Loading: If you want to use it, you have to implement it…

Welcome to this new workshop focused on the `Windows DLL Loading` internals.

`DLL` Loading is one of the most important parts of the Windows system. When you install, run, use, or hack a system, you will always use `DLL`. This `DLL` mechanism has been exploited for several years for malware development through several techniques : `DLL` injection, `DLL` sideloading, Reflective `DLL` but do you really know how Windows is loading a `DLL` ? Do you know how it links all sections ? Which structures are used to store internally ? How does it resolve dependencies ? And are you able to design your own `Perfect DLL Loader` that fully integrate with the `WIN32API`?

In this workshop, you will lose you sanity and dive into the Windows `DLL` mechanism. Armed with your decompiler and your brain, step by step, you will build your own (almost) Perfect `DLL` loader.
You will try to load from the simple `AMSI.DLL` to the most complex `WINHTTP.DLL`. At each step, you will dive deeper into the `Windows DLL Loader` and the `Windows Internals`.

Malware developers, you will be able to use this code as a `PE` loader that never failed me for the last years and a `DLL loader` that does not raise the `LoadImage` kernel callback you can use on your own `C2` beacon.

> ***WARNING**: while this is a Windows internal DISCOVERY discovery course, it is still a HIGHLY TECHNICAL workshop. You should have some entry-level knowledge on Windows systems, C programing and reverse engineering to fully enjoy the workshop.*


# Technical Prerequisites
## Official Setup
For this workshop, you have several technical prerequisites:
- A Windows 10 workstation 
- VisualStudio with `CMake` capabilities
- [IDA Freeware 8.4 or greater](https://hex-rays.com/ida-free/)
- The [Sysinternals](https://download.sysinternals.com/files/SysinternalsSuite.zip) 
- A PE Explorer such as [PEBear](https://github.com/hasherezade/pe-bear/releases/download/v0.6.7.3/PE-bear_0.6.7.3_x64_win_vs19.zip)
- A debugger such as Windbg Preview (that can be found in the Microsoft store) with [symbols cached](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-path#cache-symbols-locally) 
- Python

> IDA Freeware needs a network connection to decompile ASM into C code. Ensure that you will have a fallback internet connection (4G/5G) in case the Defcon network is unstable. The Projects given should be fully decompiled so this should not be a problem if you stick with the official setup

## I want to use my own setup cause I'm a smartty and I know better
Be my guest but you are on your own.


## Visual Studio
During the setup of `Visual Studio` ensure that the following packages are installed:
- Desktop Development with C++
    - MSVC v143 - VS 2022 C++ x64/x86
    - C++ Cmake tools for Windows
    - Windows 10 SDK (10.0.19041.0)

Then, check that you can build the projects contained in the `solutions` folders of each activity. These are CMake projects:
1. Open the folder as a project with Visual Studio
2. Wait for Visual to detect the CMake setup
3. Compile
4. Run

# Activities structures
## Directory structure
For each activity you have a dedicated folder with three items:
1. solutions: this folder contains the final working code with all comments and explanations
2. sources: this folder contains the code you have to fix. All elements that must be fixed are prefixed with the comment `WORKSHOP TODO`
3. readme.md: this file contains some explanation on what you are expected to do during this activity

## Navigate in the source code
For each activity, the file `loadlibrary.h` will contain the prototype of all functions. The new functions are listed at the end of the file. You will have to focus on these function only.

## IDA folder
The `IDA` folder contains all the `IDA` projects we will use during our investigation.

You can start with your own database, but I spent time reversing some part of the `DLLs` to help you during your investigation.


# Workshop activities summary
## Part 1 - AMSI
This project perform the basic steps to load a `DLL` or a `PE` in memory.

Once you have loaded you `DLL` in memory, you can play with the `WIN32` `API` to see the limit of this method. Then, once you have found the limit, you can use your debugging and reverse engineering skills to overcome these limitations in `Part 2`.

# Part 2 - Integration with WIN32
In this part, you will try to integrate the DLL loader with the `WIN32` `API` by registering the new `DLL` into the main internal structures including the `PEB`, the linked list and the `red&black` trees.

Before that, you will have to identify them by yourself in the `NTDLL` code.

Once everything works, try loading the `bcrypt.dll` to see some limitation on this integration

# Part 3 - Limit of PEB integration
In this part, you will overcome the limitation induced by the previous part. By reversing the `NTDLL` you will see new structures involved in the loading process.

You will have to implement them and fix the loader to successfully load the `Bcrypt.dll`

# Part 4 - Delayed loading and IAT
In this part, you will learn how it is possible to perform transparent `IAT` hijacking and how it is possible to fully integrate the delayed DLL loading without loading all the `DLL` at once.


# Part 5 - APISet
In this part you will learn about the Windows `APISet` and how you can dynamically resolve them

# Part 6 - WinHTTP
In this part, you will compile all the previous learning to successfully load the `WinHTTP` `DLL` without raising any `LoadImage` event.