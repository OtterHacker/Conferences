# Malware Development On Secured Environment - Write, Adapt, Overcome

# Overview
This workshop has been presented at the `Defcon31` event.

This workshop will give an initiation to offensive malware development in `C/C++` and how it is possible to adapt the approach depending on the security solution that must be tackled down. Different methods such as `ModuleStomping`, `DLL Injection`, `Threadless Injection` and `Hardware Breakpoint` for bypassing `EDR`'s userland hooks will be seen.

The idea is to start with a basic malware performing process injection and apply additional techniques to start evading `EDR`. At each step, some analysis on the malware will be performed to understand the differences at the system level and the `IOC` detected by the `EDR`.

At the end of this workshop, you will have all the knowledge needed to develop your own malware and adapt it to the targeted environment to escape from the basic pattern and spawn your beacons as if `EDR` didn't exist.

# Prerequisite
As said before, the goal of this workshop is to develop and analyze malwares against security products. Thus, at least on `EDR` must be installed in you workshop `VM`.

Some `EDR` give free trials such as the [Microsoft Defender For Endpoint EDR](https://signup.microsoft.com/get-started/signup?products=7f379fee-c4f9-4278-b0a1-e4c8c2fcdf7e&ru=https%3a%2f%2faka.ms%2fMDEp2OpenTrial&brandingId=28b276fb-d2a0-4379-a7c0-57dce33da0f9&ali=1).

This workshop has been explicitly designed to be run against `MDE` but feel free to use any `EDR`

# How to use this workshop
All the theoretical knowledge has been compiled in the `Part 0 - Presentation` directory. Read this material before doing the hands-on.

> TLTR : Read the PDF file, the `Part 0 - Presentation/README.md file`, and complete the `intermediate/main.c` file.

For each hands-on part, you will find in the related directory the following structure:
- `main.c` : this is a blank file containing all the instruction of what you should achieve in the workshop
- `snippet` directory : this directory contains all the code snippets you can use to develop your malware. You should be able to finalize your malware without needing to write additional code
- `intermediate` directory : this directory contains a pre-filled `main.c` file. You just have to replace the `<TODO>` parameters in the functions. If you don't want to spend too much time developing your code, you can focus on understand the code by replacing the parameters in the different functions
- `spoilers` directory : this directory contains the full solution for the workshop

> The `main.c` (especially the `spoiler/main.c`) file can be easily compiled with the `Visual Studio 2022` `cl.exe` compiler
All the code is commented so you can understand, step by step what is happening. 

# Workshop summary
- 50 minutes : Core concept on process injection
    - 10 minutes : Theoretical core concepts
    - 40 minutes : Hands on - entropy evaluation, standard process injection, `API` hooking (debugger)
- 1h30 : Standard techniques
    - 15 minutes : Theoretical concepts on `ModuleStomping` and `DLL Injection`
    - 45 minutes : Hands on - `Module stomping` - `DLL injection`
    - 30 minutes : Hands on - `ProcessHacker` and `EDR` analysis
- 1h40 : Advanced techniques
    - 10-15 minutes : Theoretical concepts - mainly `Threadless injection`, quick references to `HWBP` and `Dynamic API`
    - 1 hour : Hands on: Threadless injection (`HWBP` and `Dynamic API` code will be directly given to focus on threadless injection)
    - 30 minutes : Hands on - Follow the injection path with debugger; `EDR` analysis


The first hour will be dedicated to the workshop introduction and basic stuff about malware development. A first sample using standard process injection pattern will be presented and participant will have to take the initial code furnished (which is related to basic process injection) and implement some basic static analysis bypass such as entropy evaluation bypass or string detection masking.
Then, some test on `API` unhooking (mainly patching some `NTDLL` function with a debugger to get acquainted with hooking principle) will be performed. The idea is that at the end of this first hour, every participant will have seen at least once, a process injection, a hook and basic malware development concept. This sample will then be run against a basic `AV` to highlight the weaknesses of the standard process injection patterns.

The next 1h will be dedicated to the presentation of different techniques such as module stomping, `DLL` injection and unhooking. These techniques have been chosen among others as they can be quickly implemented and do not require extensive knowledge on `Windows` internals.
15 minutes will be taken for theoretical courses in order to explain the main concepts of these techniques.
The next 45 minutes will be used to build a simple C shellcode loader based on module stomping and DLL injection.
First, the module stomping technique will be tackled down. The use of `ProcessHacker` or `ProcessExplorer` will be used to detect the additional `DLL` loading, the principle of backed memory and how it can be leveraged to load malicious code.
Then, this example will be extended into `DLL` injection as it uses the same `WIN32API` (`LoadLibrary`) to make a link with process injection.
Again, participants are not expected to write a fully functional code from scratch in 45 minutes.

Then, for the next 30 minutes, this loader will then be put under the microscope to understand the pros and cons of the different techniques, the `IOCs` let by the injection and the behavior of the `EDR` to get the BlueTeam point of view. Some specific `IOCs` such as `MemoryAllocation` or `CreateRemoteThread` are expected to be raised by the `EDR`: the initial code sample will be messy enough to raise basic detection. During these 30 minutes, participants will have to see what detection elements are raised by the `EDR` and try to adapt their code to limit these detection.
During this malware review, an explanation about the `EDR` behavior against `WIN32API`, backed/unbacked memory and injection pattern will be presented. The goal is to point to the area of improvement that will be shown right after.

The rest of the workshop (1h40) will be dedicated to the implementation of more advanced techniques.
15 minutes will be dedicated to concepts presentation.
1 hour will be dedicated to the threadless injection technique as it is the one that can be used to avoid the use of `CreateRemoteThread` during process injection. For hardware breakpoints and dynamic `API` resolution, a theoretical explanation will be given as well as working code example if participant want to play with it, but the main point of this part is to understand, build and play with threadless injection.
The threadless injection technique will be covered in three steps:
- Hooking an existing API
- Writing a trampoline function
- Storing all of it in the remote process

The main point is to show that it is possible, with a combination of standard techniques and some creativity, to create an advanced piece of malware able to evade several detections.

Finally, the previous shellcode will be updated and rerun against the test `EDR`, the debugger and the memory analyzer to view the difference with the previous one and the flaws that should be tackled down.
The main attention point here will be to follow the track of the threadless injection code with the debugger to see how the code flow is hijacked, how the initial hook is rewritten by itself and how the `EDR` respond at each step.


