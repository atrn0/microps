#include "ip.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "net.h"
#include "util.h"

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |Version|  IHL  |Type of Service|          Total Length         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |         Identification        |Flags|      Fragment Offset    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Time to Live |    Protocol   |         Header Checksum       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Source Address                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Destination Address                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Options                    |    Padding    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct ip_hdr {
  uint8_t vhl;
  uint8_t tos;
  uint16_t total;
  uint16_t id;
  uint16_t offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t sum;
  ip_addr_t src;
  ip_addr_t dst;
  uint8_t options[0];
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to
 * protect these lists with a mutex. */
// 論理インターフェイス
static struct ip_iface *ifaces;

int ip_addr_pton(const char *p, ip_addr_t *n) {
  char *sp, *ep;
  long ret;

  sp = (char *)p;
  for (int idx = 0; idx < 4; idx++) {
    ret = strtol(sp, &ep, 10);  // 10進数
    if (ret < 0 || ret > 255) {
      return -1;
    }
    if (ep == sp) {
      return -1;
    }
    if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
      return -1;
    }
    ((uint8_t *)n)[idx] = ret;
    sp = ep + 1;
  }
  return 0;
}

char *ip_addr_ntop(const ip_addr_t n, char *p, size_t size) {
  uint8_t *u8;

  u8 = (uint8_t *)&n;
  snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
  return p;
}

void ip_dump(const uint8_t *data, size_t len) {
  struct ip_hdr *hdr;
  uint8_t v, hl, hlen;
  uint16_t total, offset;
  char addr[IP_ADDR_STR_LEN];

  // stderrをロック
  flockfile(stderr);
  hdr = (struct ip_hdr *)data;
  v = (hdr->vhl & 0xf0) >> 4;
  hl = hdr->vhl & 0x0f;
  hlen = hl << 2; /* 32bit word to 8bit word */
  fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl,
          hlen);
  fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
  total = ntoh16(hdr->total); /* net to host */
  fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
  fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
  offset = ntoh16(hdr->offset);
  fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset,
          (offset & 0xe000) >> 13, offset & 0x1fff);
  fprintf(stderr, "        ttl: %u\n", hdr->ttl);
  fprintf(stderr, "   protocol: %u\n", hdr->protocol);
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
  fprintf(stderr, "        src: %s\n",
          ip_addr_ntop(hdr->src, addr, sizeof(addr)));
  fprintf(stderr, "        dst: %s\n",
          ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask) {
  struct ip_iface *i = calloc(1, sizeof(*ip_iface));
  if (!i) {
    errorf("calloc() failure");
    return NULL;
  }

  NET_IFACE(i) = NET_IFACE_FAMILY_IP;

  ip_addr_t *u;
  if (ip_addr_pton(unicast, u) < 0) {
    errorf("failed to parse unicast address: %s\n", unicast);
    return NULL;
  }
  i->unicast = *u;

  ip_addr_t *n;
  if (ip_addr_pton(netmask, n) < 0) {
    errorf("failed to parse netmask address: %s\n", netmask);
    return NULL;
  }
  i->netmask = *n;

  // ホスト部のビットを全て1にする
  i->broadcast = *u || ~*n;

  return i;
}

/* NOTE: must not be call after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface) {}

struct ip_iface *ip_iface_select(ip_addr_t addr) {}

// IP input handler
static void ip_input(const uint8_t *data, size_t len, struct net_device *dev) {
  struct ip_hdr *hdr;

  // validate IP header
  if (len < IP_HDR_SIZE_MIN) {
    errorf("too short");
    return;
  }
  hdr = (struct ip_hdr *)data;
  // validate IP version
  if ((hdr->vhl & 0xf0) >> 4 != IP_VERSION_IPV4) {
    errorf("IP version is not IPv4");
    return;
  }
  // validate header length
  uint16_t hlen = (hdr->vhl & 0x0f) << 2;
  if (len < hlen) {
    errorf("data length is shorter than header length");
    return;
  }
  // validate total length
  uint16_t total = ntoh16(hdr->total);
  if (len < total) {
    errorf("data length is shorter than total length");
    return;
  }
  // checksum
  if (cksum16((uint16_t *)data, hlen, 0) != 0) {
    errorf("checksum not match");
    return;
  }

  uint16_t offset = ntoh16(hdr->offset);
  // More Fragments or Fragment Offset is not zero
  if (offset & 0x2000 || offset & 0x1fff) {
    errorf("fragments does not support");
    return;
  }

  debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total);
  ip_dump(data, total);
}

int ip_init(void) {
  if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
    errorf("net_protocol_register() failure");
    return -1;
  }
  return 0;
}
