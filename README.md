## Linux Malware Development (LMD)

This repo is a project on Linux Malware Development with an emphasis on understanding how advanced Linux Malware can be created. This is mainly due to the increased used of Linux Webservers, Embedded (IOT) devices, Personal OS'es etc...

### Remote Process Injection.
This include(s) enumerating all the Linux Processes that are currently running to find a process whose memory is injectable (A Process that is owned by the injecting user/process). A payload will finally be injected into this process's memory and executed for Code Execution. This makes use of the `ptrace()` system call mainly used by debuggers.
- **Shared Library Injection**: This is where we injection a malicious shared-library and load it into another process. This technique applies the same concepts as  ***Windows DLL Injection***.
- **Code Injection**: This is where we inject malicious code into the memory of another process to evade detection. The code injected should make sure that it does not tamper with the normal execution of the injected process.

### Linux Malware Defense Evasion

These include [techniques](LinuxMalwareDefenseEvasion) that can be added to the malware to remain stealthy and prevent detection by AntiViruses and other analysts in the Network. These are further categorized into the following:
 - `Self-Debugging`: This is used to make it hard for Reverse Engineers to reverse the Malware via the use of different debuggers i.e. The GNU Linux Debugger.
 - `Time-Stomping`: This is used to change the creation date of the malware to prevent detection when on disk.
 - `Static/Dynamic Analysis Evasion`: The use of specific techniques to prevent malware detection or rather behavior when it is analyzed dynamically or statically.
 - `pid-spoofing`: Spoofing other running processes to blind users/admins when running `ps -aux`.

All these techniques are described on my blog [here](https://mutur4.github.io/posts/linux-malware-development/edr/) and the code to a stealthy malware that injects into another process employing all these different techniques can be found [here]()
   

### Linux RootKits.
A dive into 'ring 0' for more advanced stealth, attacks, and techniques. 
 - Abusing eBPF for Linux Malware Development.

### Persistence Techniques
This will include a set of techniques that will be used for persistence (making sure that after a hard reboot) our malware will still be up and running. 

### A Linux C2 (Upcoming Project) - [Mammoth Linux C2](https://github.com/mutur4/Mammoth-Linux-C2)

The development of a Linux-based C2 that will/should allow an attacker to communicate with an implant for backdoor access/data exfil/KeyLogging etc... 
