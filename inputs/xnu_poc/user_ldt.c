#include <architecture/i386/table.h>
#include <i386/user_ldt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "hex.h"

int allocation(){
	char *data = malloc(0x100);
    memset(data, 0, 0x100);
	if(i386_set_ldt(LDT_AUTO_ALLOC, (union ldt_entry *)data, 3) < 0){
		perror("set_ldt");
		return 1;
	}

}

void leak(){
	char *data = malloc(0x100);
	memset(data, 0, 0x100);
	size_t start = 0;
	size_t num_sels = 0x100;

	// test
	if( i386_get_ldt(LDT_AUTO_ALLOC, (union ldt_entry *)data, 0x100) < 0){
		perror("get_ldt");
		return;
	}
	DumpHex(data, 0x100);
}

int main(){
	allocation();
	leak();
}
