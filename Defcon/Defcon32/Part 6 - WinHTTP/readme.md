# Part 6 - WinHTTP

# Main objectives
The main objective for this part is to successfully load the WinHTTP and perform an HTTP request.

# Generalize the custom loader
The first step is to generalize the custom loader so that every DLL loaded and sub-dll loaded will use it instead of LoadLibrary.

For that, look at the IAT and replace the right functions to make it work.

Then, look at every part of the code to remove any references to LoadLibrary functions family.

# Custom Win32API
The last step is to use a fully custom GetProcAddress and GetModuleHandle.

Use all the knowledge you gathered from the workshop to implement the GetProcAddress and the GetModuleHandle by hand.

# Run it through procmon
Run your program under procmon scrutiny, is there any additional ImageLoad event ?