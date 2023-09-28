
#### Enumerate Process

The `enumProcs` function will enumerate all the processes by reading and parsing the `/proc` directory to find processes that belong to us (these are processes that have the same PID as our main 'injecting' process). This is because we cannot inject or rather attach into processes that were started by another user. 

#### Remote mmap()

After a suitable process is enumerated and returned, the memory maps `/proc/maps` are parsed to find a region that is executable. The first stage shellcode is then injected into this region to allocate a new mapping/address into the process as `rwx`. A second-stage payload is injected into the mapped region to connect back to the attacker as a POC running in the context of the injected process. 
