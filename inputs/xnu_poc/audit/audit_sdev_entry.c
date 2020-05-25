#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>

#include <bsm/audit.h>

struct  au_qctrl64 {
    u_int64_t       aq64_hiwater;
    u_int64_t       aq64_lowater;
    u_int64_t       aq64_bufsz;
    u_int64_t       aq64_delay;
    int64_t         aq64_minfree;
};
typedef struct au_qctrl64 au_qctrl64_t;

union auditon_udata {
    char            *au_path;
    int         au_cond;
    int         au_policy;
    int64_t         au_cond64;
    int64_t         au_policy64;
    int         au_trigger;
    au_evclass_map_t    au_evclass;
    au_mask_t       au_mask;
    au_asflgs_t     au_flags;
    auditinfo_t     au_auinfo;
    auditpinfo_t        au_aupinfo;
    auditpinfo_addr_t   au_aupinfo_addr;
    au_qctrl_t      au_qctrl;
    au_qctrl64_t        au_qctrl64;
    au_stat_t       au_stat;
    au_fstat_t      au_fstat;
    auditinfo_addr_t    au_kau_info;
    au_ctlmode_t    au_ctl_mode;
    au_expire_after_t   au_expire_after;
};

void allocation(){
	// auditon
	// cmd A_SETSFLAGS or A_SETPMASKsd
	union auditon_udata *udata = malloc(sizeof(union auditon_udata));
	memset(udata, 0, sizeof(union auditon_udata));
	udata->au_flags = sizeof(union auditon_udata);


	if(syscall(351, A_SETSFLAGS, udata, sizeof(union auditon_udata)) < 0){
		perror("allocation");
	} 
}

int main(){
	allocation();
}
