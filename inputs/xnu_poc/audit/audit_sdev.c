#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <bsm/audit_session.h>

int allocation(){
	int fd = open("/dev/auditsessions", O_RDONLY);
	if(fd < 0){
		perror("open");
		exit(0);
	}
	return fd;	
}

void leak(int fd){
	char buffer[0x100];
	read(fd, buffer, 0x100);
}

void test(){
	au_sdev_handle_t *h;
	h = au_sdev_open(AU_SDEVF_ALLSESSIONS);
    if (h == NULL)
		return;
	auditinfo_addr_t aio;	
	int event;
	if (au_sdev_read_aia(h, &event, &aio) != 0)
		return;
	printf("new event\n");

}

// the event is generated from kernel, or auditon, coredump, setauid(root), setaudit_addr(root),. if there are no events, nothing can be read.
// the event capture rule is controled by root users
// check apple's securityd for more details. (auditevents.cpp)
// https://github.com/apple-opensource-mirror/securityd
// additional resource: https://github.com/meliot/filewatcher
int main(){
	//int fd = allocation();
	test();
}
