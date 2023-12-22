These are the various Linux-Process-Injection techniques as described in the main repository:

### Shellcode-Injection 

The shellcode injection technique provided here follows the following steps to initiate code injection in the memory of a live Firefox process:

#### *Process Enumeration*

The `enumProcs` function will enumerate all the processes by reading and parsing the `/proc` directory to find processes that belong to us *(these are processes that have the same PID as our main 'injecting' process)*. This is because we cannot inject or rather attach into processes that were started by another user. 

#### *Remote Mmap*

After a suitable process is enumerated and returned, the memory maps `/proc/maps` are parsed to find a region that is executable. The first stage shellcode is then injected into this region to allocate a new mapping/address into the process as `rwx`. A second-staged payload is then injected and this will spawn a new thread that will connect back to the attacker for PoC. 

The provided code can be modified to inject into any process of you choice, the current code injects into a firefox process. 
