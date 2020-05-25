#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

void allocation(int *fds){
	if(pipe(fds) < 0){
		perror("pipe");
		exit(1);
	}
}

void leak(int *fds){
	char *buf = malloc(0x100);
	memset(buf, 0, 0x100);

	write(fds[1], "hello", 5);
	read(fds[0], buf, 5);
	printf("%s", buf);

	write(fds[1], " world", 6);
	read(fds[0], buf, 6);
	printf("%s\n", buf);
}

int main(){
	int fds[2] = {0};
	allocation(fds);
	leak(fds);
}
