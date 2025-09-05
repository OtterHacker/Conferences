# Password
The password for the ZIP file is Password@123!

# Reach the Nirvana

# Introduction
This workshop aims to weaponize the [Nirvana Hooking](http://publications.alex-ionescu.com/Recon/Recon%202015%20-%20Hooking%20Nirvana%20-%20Stealthy%20Instrumentation%20Techniques.pdf) technique throug 4 different techniques:
- Simple *SYSRET* hijack to understand how NirvanaHooking works and how it is possible to change the *SYSRET* returned by the *KERNEL*
- DLL proxying to change execution flow to see a first application of NirvanaHooking and *SYSRET* spoofing
- Remote process injection to see how Nirvana Hooking can be used to trigger code execution on a remote process
- Sleep obfuscation through thread killing and spawn

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
2. sources: this folder contains the code you have to fix. All elements that must be fixed are prefixed with the comment `TODO`
3. readme.md: this file contains some explanation on what you are expected to do during this activity

## IDA folder
The ntoskrnl.exe.i64 contains the `IDA` projects we will use during our investigation.

You can start with your own database, but I spent time reversing some part of the `DLLs` to help you during your investigation.

# Part 1 - Syscall Hijack
In this part you will learn:
- How to define a Nirvana Hook
- How to register the hook
- How to change the SYSRET returned by the KERNEL

## Define a NirvanaHook
First, decompile *ntoskrnl.exe* and look at the *KiSetupForInstrumentationReturn* function:

```c
void __fastcall KiSetupForInstrumentationReturn(PKTRAP_FRAME TrapFrame)
{
  void *InstrumentationCallback; // r8

  InstrumentationCallback = KeGetCurrentThread()->ApcState.Process->InstrumentationCallback;
  if ( InstrumentationCallback )
  {
    if ( TrapFrame->SegCs == 51 )
    {
      TrapFrame->R10 = TrapFrame->Rip;
      TrapFrame->Rip = (unsigned __int64)InstrumentationCallback;
    }
  }
}
```

- How does the KERNEL redirect the execution flow to the calling userland code ?
- What does it imply for the hook format ? 
- If TrapFrame represents a structure containing the userland thread context, what registry will contain the address of the function that has performed the syscall when the hook is run ?
- How can the hook restore the execution flow after execution ?

## CFG implementation at KERNEL level
The *NtSetInformationProcess* is the function used to register a Nirvana Hook.

By reversing *ntoskrnl.exe* answer the following questions:
- Is CFG validation implemented at KERNEL level ?
- What are the functions used to check CFG ?
- Can Nirvana hook be used to bypass CFG validation ?

## Hands on
The folder *1 - Syscall Hijack/sources* contains a code that is supposed to:
- Perform a call to *NtAllocateVirtualMemory*
- Register a NirvanaHook
- Perform a second call to *NtAllocateVirtualMemory* and intercepting the *SYSRET* to raise a 0xc0000005 error

Fix all the TODO in the code !


# Part 2 - DLL Proxying
The goal of this part is to weaponize the SYSRET hijacking capabilities by performing a process injection through DLL proxying.

The PE *target/NirvanaTarget.exe* is a PE that:
- Loads the DLL libcrypto.dll in an unsecured way
- Perform a memory allocation of an RWX section and check that the allocation succeeds
- Write data on the section allocated and check that the write operation succeeds
- Execute the data that has been written on the allocated section

The goal of this part is to:
- Use DLL proxying on libcrypto.dll to inject a NirvanaHook on the targeted PE
- Define a hook that will perform a process injection by abusing the allocation, write and execution primitive already configured on the PE

## Understand the binary
First decompile the *NirvanaTarget.exe* binary (or just open its C code).

- What are the different SYSCALL that will be made ?
- Can we abuse any SYSRET ?
- Is there a way to hijack the memory allocation ?
- Is there a way to prevent the write operation ?
- Is there a way to ensure that the target will think the write operation succeeded ?

## Hands on
The folder *2 - DLL Proxying* contains 2 directories:
- *target*: contains the *NiravaTarget.exe* PE
- *sources*: contains the source code of a DLL that will be used for the DLL proxying

### Execute my payload
1. Compile the source project, it will create the *libcrypto.dll* file
2. In the same directory put: *libcrypto.dll*, *libcryptox32.dll*, *NirvanaTarget.exe*
3. Open a *ncat* listener on *127.0.0.1:8000*
4. Run *NirvanaTarget.exe*
5. Wait for the reverse shell callback

# Part 3 - SetProcessInjection
## Nirvana Hook on remote process
Check the prototype of *NtSetInformationProcess* function
- Is there any parameter that say that this function can be used to trigger a remote process ?

Decompile the *ntoskrnl.exe* and look at the *NtSetInformationProcess* code.
- Do you see any limitation related to the use of *NtSetInformationProcess* on a remote process ?

Finally, how could we use NtSetInformationProcess to perform a process injection on a remote process ?

## Hands on
The folder *3 - SetProcessInformation/sources* contains a code source of a malware performing a process injection.

The payload is a classic reverse shell that callback on *127.0.0.1:8000*

# Part 4 - Nirvana Sleep
This part shows how NirvanaHook can be used to perform a sleep obfuscation on a C2 beacon by killing the beacon thread instead of putting it into sleep 
The NirvanaSleepObfuscation works by saving the thread context and the stack state on the heap and kill the beacon thread.

## Introduction
- What are the different steps needed to save a thread context ?
- How can I ensure that the thread will be recreated at a specific moment ?
- How can I restore the whole thread context and stack ?



## Context saving
The thread context is saved using RtlCaptureContext. The stack size to backup is computed by computing the difference between the stack pointer when running the entry point and the stack pointer when performing the sleep:
_____________________________________________________
ENTRY | FCT 1 | FCT 2 | FCT 3 | FCT 4 | NirvanaSleep
_____________________________________________________
      <----- SP Nirvana - SP Entry----->  

## Before killing the thread
Before killing the thread, the current system time is saved and will be used to wake up the beacon. 

Likewise, the NirvanaHook is registered. This hook will be called every time the main thread performs a syscall. It will compare the current system time with the one stored before killing the beacon thread. If the difference is more than the sleep time set, then the hook will restart the beacon thread.

Then the whole beacon image and heap are obfuscated using a simple XOR encryption and the different section are reprotected in RW, then the thread is killed using the ExitThread API. 

## Waking up the thread
The Nirvana hook will wake up the beacon thread (in fact it will recreate it). When the Nirvanahook detect that the beacon must be waked up, it will call a specific function. This function goal is to deobfuscate the beacon image and heap, reset the thread context and rerun the thread.

Yes we are using CreateThread, but it is called from the process itself, so not an IOC. If an EDR starts to flag legit thread creation, we will have some trouble. However, the thread will be created on an address that is not always known by the system, so this could be an IOC but it's dependent on the injection technique (VirtualAlloc/ModuleStomping/Threadless injection in known DLL...) you used so I will not spend too much time on this subject.

## Restoring the context
### The stack
The first thing to restore is the stack. But this can be kinda tricky as if we copy the backup stack at the current RSP address, any function call performed by the awake function will write on the backup stack and erase important data.

____________________________________
ThreadStart | AWAKE | BACKUP STACK
____________________________________
If the AWAKE stack frame is growing, it will start rewriting the backup stack. The awake stack must be written after the backup stack. Thus, at the beginning of the awake function, we will move the whole AWAKE stack frame to make room for the backup stack.

________________________________________________
ThreadStart |                     |     AWAKE
________________________________________________
Then we can simply copy the back stack in the hole created:
________________________________________________
ThreadStart |     BACKUP STACK    |     AWAKE
________________________________________________

It avoids having a stack like this when the awake function stack grows
____________________________________
ThreadStart | AWAKE  BACKUP STA | CK
____________________________________

This is done by the following code 
```c
DWORD stack_frame_size  = GetStackFrameSize();
PVOID rsp = (PVOID)get_rsp();
// Compute the offset
DWORD64 offset = stack_frame_size + sleep_info->stack_backup_size + 0x28;
// Copy the stack
win32_memcpy((PVOID)((DWORD64)rsp-2*offset),(PVOID)((DWORD64)rsp-offset), 0x28 + sleep_info->stackBackupSize);
// Set the new stack pointer
set_rsp((DWORD64)rsp-offset);
```

Once the space has been created, it is possible to simply copy the backup stack in it. However, there is a problem. If a previous variable pointed a value on the previous stack, the value will not be right. So we have to perform a relocation like routine to ensure that all address on the stack does not reference address on the previous stack:
```c
for(int i = 0; i < sleep_info->stack_backup_size; i += sizeof(PVOID)){
    // Check if the value is an address and if it look like pointing to the old stack address
    if(*(DWORD64*)((DWORD64)sleep_info->stack_backup + i) < old_rsp_end && *(DWORD64*)((DWORD64)sleep_info->stack_backup + i) > old_rsp_start){
        // Add the new stack offset to the address
        *(DWORD64*)((DWORD64)sleep_info->stack_backup + i) += stackOffset;
    }
}
```


## The thread context
As always, the thread context is the nice one. It is possible to change the thread context by using the NtContinue API.
Do not forget to change the RIP and the RSP. The RIP must point to the next instruction in the beacon routine. If it is not changed, you will enter again in the Sleep runtime.

The RSP must be set to the new RSP created right before.