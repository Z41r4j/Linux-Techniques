## Linux Malware Development (LMD)

This is a repository that includes code related to Linux Malware. These will range from the following categories:
### Remote Process Injection.
This include(s) enumerating all the Linux Processes that are currently running to determine a process that we have permission to manipulate its memory. A shellcode will finally be injected into the process's memory and executed for Code Execution. This makes use of the `ptrace()` system call. 

### Linux Malware Defense Evasion

These include techniques that can added to the malware to remain stealthy and prevent detection by AntiViruses. These are further categorized into the following:
 - `Self-Debugging`: This is used to make it hard for Reverse Engineers to reverse the Malware via the use of different debuggers i.e. The GNU Linux Debugger.
 - `Time-Stomping`: This is used to change the creation date of the malware to prevent detection when on disk.
 - `Static and Dynamic Analysis Evasion`: The use of specific techniques to prevent malware detection or rather behavior when it is analyzed dynamically or statically.
 - `pid-spoofing`: Spoofing other running processes to blind users/admins when running `ps -aux`. 
   
### A Linux C2 (Upcoming Project).

The development of a Linux-based C2 that will/should allow an attacker to send and receive commands.

### Linux RootKits.
A dive into 'ring 0' for more advanced stealth, attacks, and techniques. 
 - Abusing eBPF for Linux Malware Development. 
