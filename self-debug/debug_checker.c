#define _GNU_SOURCE

#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include <sys/ptrace.h>

void self_debug(union sigval valz){
        pid_t pid = valz.sival_int;

        if((ptrace(PTRACE_TRACEME, pid, NULL, NULL)) < 0){
                fprintf(stderr, "Debugger detected!");
                _exit(-1);
        }

}

int main(int argc, char **argv){
        struct sigevent event;
        struct itimerspec timer;

        timer_t timer_id;

        event.sigev_notify = SIGEV_THREAD;
        event.sigev_notify_function = &self_debug;
        event.sigev_value.sival_int = getpid();
        event.sigev_notify_attributes = NULL;

        if((timer_create(CLOCK_REALTIME, &event, &timer_id)))
                _exit(-1);


        timer.it_value.tv_sec = 1;
        timer.it_interval.tv_sec = 3; //repeat the check at intervalz of 3 seconds 

        if((timer_settime(timer_id, 0, &timer, NULL)))
                _exit(-1);

        getchar();

        return 0;
}
