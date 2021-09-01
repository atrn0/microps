#include "udp.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ip.h"
#include "util.h"

struct pseudo_hdr {
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t protocol;
  uint16_t len;
};

struct udp_hdr {
  uint16_t src;
  uint16_t dst;
  uint16_t len;
  uint16_t sum;
};

int udp_endpoint_pton(const char *p, struct udp_endpoint *n) {
  char *sep;
  char addr[IP_ADDR_STR_LEN] = {};
  long int port;

  sep = strrchr(p, ':');
  if (!sep) {
    return -1;
  }
  memcpy(addr, p, sep - p);
  if (ip_addr_pton(addr, &n->addr) == -1) return -1;
  port = strtol(sep + 1, NULL, 10);
  if (port <= 0 || port > UINT16_MAX) return -1;
  n->port = hton16(port);
  return 0;
}

char *udp_endpoint_ntop(const struct udp_endpoint *n, char *p, size_t size) {
  size_t offset;

  ip_addr_ntop(n->addr, p, size);
  offset = strlen(p);
  snprintf(p + offset, size - offset, ":%d", ntoh16(n->port));
  return p;
}

static void udp_dump(const uint8_t *data, size_t len) {
  struct udp_hdr *hdr;

  flockfile(stderr);
  hdr = (struct udp_hdr *) data;
  fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
  fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
  fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

static void udp_input(const uint8_t *data, size_t len, ip_addr_t src,
                      ip_addr_t dst, struct ip_iface *iface) {}

ssize_t udp_output(struct udp_endpoint *src, struct udp_endpoint *dst,
                   const uint8_t *data, size_t len) {}

int udp_init(void) {
  if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1) {
    errorf("ip_protocol_register() failure");
    return -1;
  }
  return 0;
}
