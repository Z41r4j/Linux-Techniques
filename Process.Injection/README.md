There are various Process Injection techniques that are provided in this directory as stated in the main `README`.
## Shellcode Injection 

The shellcode injection technique provided here follows the following process to initiate the code injection:

#### Process Enumeration

The `enumProcs` function will enumerate all the processes by reading and parsing the `/proc` directory to find processes that belong to us (these are processes that have the same PID as our main 'injecting' process). This is because we cannot inject or rather attach into processes that were started by another user. 

#### Remote Mmap

After a suitable process is enumerated and returned, the memory maps `/proc/maps` are parsed to find a region that is executable. The first stage shellcode is then injected into this region to allocate a new mapping/address into the process as `rwx`. A second-staged payload is then injected and this will spawn a new thread that will connect back to the attacker for POC. 

The provided can be modified to inject into any process of you choice, the current code injects into a firefox process. 


## Shared Library Injection

The shared library injection technique is similar to the Windows DLL Injection attack. When create a malicious shared library and load this into a remote process. 
