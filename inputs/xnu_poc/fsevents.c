#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main(){
	int fd = open("/dev/fsevents", 0);
	if(fd < 0){
		perror("open");
	}
}
