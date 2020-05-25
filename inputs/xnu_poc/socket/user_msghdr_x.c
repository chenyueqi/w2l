#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <uuid/uuid.h>

struct msghdr_x {
	void		*msg_name;	/* optional address */
	socklen_t	msg_namelen;	/* size of address */
	struct iovec 	*msg_iov;	/* scatter/gather array */
	int		msg_iovlen;	/* # elements in msg_iov */
	void		*msg_control;	/* ancillary data, see below */
	socklen_t	msg_controllen;	/* ancillary data buffer len */
	int		msg_flags;	/* flags on received message */
	size_t		msg_datalen;	/* byte length of buffer in msg_iov */
};

int main(){

	struct sockaddr_in addr;

	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if(sock < 0){
		printf("couldn't create socket\n");
		exit(1);
	}

	// set reusable
	int opt = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(6666);
	if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0){
		printf("couldn't bind to the socket\n");
		exit(1);
	}

	// recv here

	struct msghdr_x msg;
	memset(&msg, 0, sizeof(msg));
	
	msg.msg_name = malloc(0x100);
	msg.msg_namelen = 0x100;
	msg.msg_control = malloc(0x100);
	msg.msg_controllen = 0x100;
	msg.msg_iov = malloc(sizeof(struct iovec));
	msg.msg_iovlen = 1;
	msg.msg_iov->iov_base = malloc(0x100);
	msg.msg_iov->iov_len = 0x100;

	syscall(480, sock, &msg, 1, 0);

}
