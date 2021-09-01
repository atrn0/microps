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
  uint16_t len; /* UDP header + data */
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
                      ip_addr_t dst, struct ip_iface *iface) {
  struct pseudo_hdr pseudo;
  struct udp_hdr *hdr;
  uint16_t psum;
  char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];

  if (len < sizeof(*hdr)) {
    errorf("too short");
    return;
  }

  hdr = (struct udp_hdr *) data;
  if (len != ntoh16(hdr->len)) {
    errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
    return;
  }
  pseudo.src = src;
  pseudo.dst = dst;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_UDP;
  pseudo.len = hton16(len);
  psum = ~cksum16((uint16_t *) &pseudo, sizeof(pseudo), 0);
  if (cksum16((uint16_t *) hdr, len, psum) != 0) {
    errorf("checksum error: sum=0x%04x, verify=0x%04x",
           ntoh16(hdr->sum),
           ntoh16(cksum16((uint16_t *) hdr, len, -hdr->sum + psum)));
    return;
  }
  debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
         ip_addr_ntop(src, addr1, sizeof(addr1)),
         ntoh16(hdr->src),
         ip_addr_ntop(dst, addr2, sizeof(addr2)),
         ntoh16(hdr->dst),
         len,
         len - sizeof(*hdr));
  udp_dump(data, len);
}

ssize_t udp_output(struct udp_endpoint *src, struct udp_endpoint *dst,
                   const uint8_t *data, size_t len) {
  struct udp_hdr *hdr;
  uint8_t buf[IP_PAYLOAD_SIZE_MAX];
  struct pseudo_hdr pseudo;
  uint16_t total, psum = 0;
  char ep1[UDP_ENDPOINT_STR_LEN], ep2[UDP_ENDPOINT_STR_LEN];

  if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
    errorf("too long");
    return -1;
  }

  total = sizeof(*hdr) + len;

  pseudo.src = src->addr;
  pseudo.dst = dst->addr;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_UDP;
  pseudo.len = hton16(total);
  psum = ~cksum16((uint16_t *) &pseudo, sizeof(pseudo), 0);

  hdr = (struct udp_hdr *) buf;
  hdr->src = src->port;
  hdr->dst = dst->port;
  hdr->len = hton16(len);
  hdr->sum = 0;
  hdr->sum = cksum16((uint16_t *) hdr, total, psum);

  memcpy(buf + sizeof(*hdr), data, len);

  debugf("%s => %s, len=%zu (payload=%zu)",
         udp_endpoint_ntop(src, ep1, sizeof(ep1)), udp_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
  udp_dump((uint8_t *) hdr, total);

  if (ip_output(IP_PROTOCOL_UDP, buf, total, src->addr, dst->addr) == -1) {
    errorf("ip_output() failure");
    return -1;
  }

  return len;
}

int udp_init(void) {
  if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1) {
    errorf("ip_protocol_register() failure");
    return -1;
  }
  return 0;
}
