#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <unistd.h>


int allocation(){
	int fd = open("/dev/ptmx", O_RDWR); 
	if(fd<0){
		perror("open");
	}
}

void leak(int fd){

	
}

int main(){
	int fd = allocation();
}
