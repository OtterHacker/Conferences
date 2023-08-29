# Defcon31 : Malware on secured environment

> No time will be allowed during the workshop to deploy the initial setup. If you didn't do your setup before the workshop, you will not be able to attend to 75% of the assignments.

> It approximately takes 45 minutes to perform the initial setup. Please take this time to fully enjoy the workshop.

# Information
In this workshop, you will play with the `Microsoft Defender For Endpoint EDR`, `C2` beacon and `C` code. Thus, you are required to have your own `EDR`, `C2` and compiler.

Don't panic, a `Microsoft Defender For Endpoint` has been setup for you and the enrollment script is configured on the provided VM to be run automatically at startup. However, if you prefer to use your own `VM` and `MDE` instance, feel free to use your own. However, I will not provide any help for this deployment.

Likewise, an opensource/freeware `C2` will be used (`Covenant`). You can try to use any other `C2` (`CobaltStrike` with `AceLDR` should work) but I will not provide any help during the `Workshop` for bugs related to the custom `C2` beacons (got troubles with MSF without packer for example).

You are free to use whatever tool/technology you want for the workshop, but I strongly recommend sticking with the one I provide you or at least perform the initial setup as a fallback solution.

> **I will not PROVIDE ANY SUPPORT TO ANYONE USING A CUSTOM SETUP** but I will be glad to help anyone trying to deploy the "official" setup.

# Ahead from the Workshop:
## Install MDE
- Download and install the Windows VM (https://drive.google.com/drive/folders/1YIP9uHAdHzblcX1dOnedN_9fnvnfzRls?usp=sharing)
- Run the VM and perform the initial configuration (username and password)
- Connect to the https://security.microsoft.com website and authenticate using the following credentials
```
user : defcon@otterhacker2.onmicrosoft.com   
password : !4;DE"A*+$-nJOicJ8Tt
mfa : scan the qrcode `authenticator.png` with the `GoogleAuthenticator` or `Microsoft Authenticator App`
```
- Check that a new entry with your hostname is present here : https://security.microsoft.com/machines?category=endpoints. You can check the `Last device update` field. It can take up to 30 minutes.
- Try to run a mimikatz or other to check that an event is raised on the MDE console.
- You can shut down your VM until the Workshop

> Errors can happen, if you f*ck with the `Microsoft` account by adding additional `MFA` or by modifying the password, please send me a message so I can revert the modification before it impacts everyone !

## Install Covenant
All along the workshop, we will work with `Covenant` beacons. On the Windows machine or on another Linux VM, install Covenant (https://github.com/cobbr/Covenant/wiki/Installation-And-Startup).

A Covenant has been installed on the Windows VM in the `C:\Program Files\Covenant directory``. Feel free to use it. The default credentials are:
``` 
defcon
defcon
```
- Try to create your listner and grunt.
- Upload the grunt on the Workshop VM (disable Defender if it is flagged)
- Run the grunt on the Workshop VM and check you have a successfully callback on your C2 console
    | Your VM should be on the same network that your Covenant C2

## Check that your C toolchain is working
You will have to compile C code all along the workshop. I only provide support for VisualStudio CLI compiler but you can try your own toolchain.

- Take a code in the SimpleLoader `spoiler` directory
- Try to compile the `main.c` file (all dependencies are in the directory).
```bash
# This path can change depending on you VisualStudio version.
# To get the right path look at "x86_x64 Cross Tools Command Prompt for VS 2022" application
# Open File Location > Properties on the shortcut > Get the 
cmd.exe
"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsx86_amd64.bat"
powershell.exe
cl.exe main.c
```

If you really want a VisualStudio project you must :
1. Disable CRT Warnings : https://stackoverflow.com/questions/16883037/remove-secure-warnings-crt-secure-no-warnings-from-projects-by-default-in-vis
2. Disable UNICODE support : https://developercommunity.visualstudio.com/t/turn-off-unicode/1077309

I strongly discourage the use of VisualStudio project as it can be quite painful to maintain all along the project if you are not familiar with it.

Moreover, I will not take any time to debug your VisualStudio project during the workshop.

# Nothing work
If you have any troubles, please, feel free to send me a mail or a pm:
- Twitter: @OtterHacker
- Mail : defcon.otter@gmail.com