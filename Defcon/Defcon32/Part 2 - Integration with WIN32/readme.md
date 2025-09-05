# Part 2 - Integration to Win32

# Dig into GetProcAddress
Use the GetProcAddress as the starting point of you investigation.

Try to understand how the GetProcAddress work and what internal structure it is using to find the load DLL

# Internal Structure
Gather as much information as possible on the internal structure and try to understand the different functions needed to fill up the structures and how we can retrieve dynamically their address.












        






# Spoilers
GetProcAddress -> ntdll!LdrGetProcedureAddressForCaller
find ref of LdrpModuleBaseAddressIndex -> LdrpInsertModuleToIndexLockHeld
find ref of LdrpInsertModuleToIndexLockHeld -> LdrpMapDllWithSectionHandle
We find the two functions :           
        LdrpInsertDataTableEntry((__int64)pLdrEntry);
        LdrpInsertModuleToIndexLockHeld(pLdrEntry, ntHeaders1);
