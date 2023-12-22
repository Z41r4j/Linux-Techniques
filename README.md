## Linux Malware Development

This is a project on <strong>Linux Malware Development</strong> with an emphasis on understanding how advanced Linux Malware can be created. This is mainly due to the increased use of Linux Webservers, Embedded (IoT) devices, Personal OS'es etc...

### Remote Process Injection
A technique that includes running code in the context of another process to avoid detection. The technique begins by enumerating all <strong>live</strong> Linux processes to find a process whose memory is injectable *(a process that is owned by the injecting user/process)*. A payload will finally be injected into this process's memory and executed for Code Execution. This makes use of the `ptrace()` syscall commonly used by debuggers.
- **Shared-Library-Injection**: This is where we inject a malicious shared-library and load it into another process. This technique applies the same concepts as  ***Windows DLL Injection***.
- **Code-Injection**: This is where we inject malicious code into the memory of another process to evade detection. The code injected should make sure that it does not tamper with the normal execution of the victim process.

### Linux Malware Defense Evasion

These include [techniques](Linux-Malware-Defense-Evasion) that can be added to the malware to remain stealthy and prevent detection by AntiViruses and other analysts in the Network. These are further categorized into the following:
 - `Self-Debugging`: This is used to make it hard for Reverse Engineers to reverse the Malware via the use of different debuggers i.e. The GNU Linux Debugger.
 - `Time-Stomping`: This is used to change the creation date of the malware to prevent detection when on disk.
 - `Static/Dynamic Analysis Evasion`: The use of specific techniques to prevent malware detection or rather behavior when it is analyzed dynamically or statically.
 - `pid-spoofing`: Spoofing other running processes to blind users/admins when running `ps -aux`.
 - `encryption/obfuscation`: This is the process of using a network protocol that encrypts or obfuscates network traffic to prevent the detection of unsual traffic in a network. 

Most of all these techniques are described on my blog [here](https://mutur4.github.io/posts/defense-evasion/)
   

### Linux RootKits.
A dive into 'ring 0' for more advanced stealth, attacks, and techniques. 
 - Abusing eBPF for Linux Malware Development.

### Persistence Techniques
This will include a set of techniques that will be used for persistence (making sure that after a hard reboot) our malware will still be up and running. 


### A Linux C2 (Upcoming Project) - [Mammoth-Linux-C2](https://github.com/mutur4/Mammoth-Linux-C2)

The development of a Linux-based C2 that will/should allow an attacker to communicate with an implant for backdoor access/data exfil/KeyLogging etc... 
