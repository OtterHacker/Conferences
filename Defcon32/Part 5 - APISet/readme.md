# Part 5 - APISet

# Main objectives
Understand what are API Set and how is it possible to map them to the different DLL

# Use of APISet
Open `amsi.dll` with `PEBear`. Look at the imported DLL and locate the different APISet.

# Understand how they are resolved
The APISet are resolved when a DLL is loaded. From KERNEL32!LoadLibrary, try to find which functions are used by Windows to resolve these API.

Remember that an APISet is not a DLL, so its redirection must be resolved as soon as possible. 

# Implement the APISet 
Fix the code and implement the APISet