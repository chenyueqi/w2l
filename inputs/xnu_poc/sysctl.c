#include <unistd.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

struct sysctl_args{
	size_t *name;
	size_t namelen;
	void *old;
	size_t *oldlenp;
	void *new;
	size_t newlen;
};

int main(){
	struct sysctl_args args;
	memset(&args, 0, sizeof(args));

	size_t size = 0x100;
	char *newname = malloc(0x100);
	memset(newname, 0, 0x100);
	int name[] = {KERN_PROCARGS, KERN_SYSV};

	args.name = name;
	args.namelen = 2;
	args.old = newname;
	args.oldlenp = &size;

	if(syscall(202, &args) < 0){
		perror("sysctl");
	}
}
