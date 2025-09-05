# Part 3 - Limit of PEB integration

# Main objectives
Extend the integration of DLL into the Windows structure

# Bcrypt.dll
With the code of Part 2, try to load `C:\Windows\System32\bcrypt.dll` and look at the entrypoint status code.
A status code of 0 means that the entrypoint didn't load correctly. 

Using IDA and Windbg, try to identify the function that is not working.

# NTDLL reverse engineering
Once you have located the function that makes the entrypoint crash, try to identify how it is possible to fix it.

# Time to implement
Fix the Part 4 code...