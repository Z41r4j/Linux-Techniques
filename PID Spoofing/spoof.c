#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#define CMDLINE_LEN 2048

//a process linked-list 
typedef struct process{
        char cmdline[CMDLINE_LEN];
        struct process *next; 
}PROCESS, *PPROCESS;

PPROCESS spoof_procs(int *size){
        PPROCESS head = NULL;
        PPROCESS curr = NULL;
        int ssize = 0;
        DIR *dir = opendir("/proc"); 

        if(!dir) return NULL;

        struct dirent *e; 

        while((e = readdir(dir)) != NULL){
                //check the process names
                if ((atoi(e->d_name) <= 0) || e->d_type != DT_DIR)
                        continue;
                char path[CMDLINE_LEN];


                snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);

                int fd = open(path, O_RDONLY, 0); // The <fd> returned  
                if (fd < 0) continue;

                char cmdline[CMDLINE_LEN];

                int read_sz = read(fd, cmdline, sizeof(cmdline));

                close(fd);

                if(read_sz <= 0) continue;

                PPROCESS process = (PPROCESS) malloc(sizeof(PROCESS));

                if(!process){ close(fd); closedir(dir); return NULL; }

                strncpy(process->cmdline, cmdline, sizeof(cmdline));
                process->next = NULL;

                if(!head) { head = process; curr = process; }
                else {curr->next=process; curr = process; }

                ++ssize;
        }

        *size = ssize;
        closedir(dir);
        return head;

}

int main(int argc, char **argv){
        int size = 0;
        PPROCESS head = spoof_procs(&size);
        PPROCESS temp = NULL;

        unsigned char *procs[size];
        temp = head;

        int idx = 0x0;

        while(temp != NULL && idx <= size){
                procs[idx++] = temp->cmdline;
                temp = temp ->next;
        }

        srand(time(NULL));
        idx = rand() % size;

        printf("[spoof as]: %s\n", procs[idx]);
        strcpy(argv[0], procs[idx]);

        return 0;
}
