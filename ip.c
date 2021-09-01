#include "ip.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
#include "util.h"
#include "arp.h"

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

//IPの上位プロトコル
struct ip_protocol {
  struct ip_protocol *next;
  uint8_t type;
  void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

struct ip_route {
  struct ip_route *next;
  ip_addr_t network;
  ip_addr_t netmask;
  ip_addr_t nexthop;
  struct ip_iface *iface;
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to
 * protect these lists with a mutex. */
// 論理インターフェイス
static struct ip_iface *ifaces;
static struct ip_protocol *protocols;
static struct ip_route *routes;

int ip_addr_pton(const char *p, ip_addr_t *n) {
  char *sp, *ep;
  long ret;

  sp = (char *) p;
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
    ((uint8_t *) n)[idx] = ret;
    sp = ep + 1;
  }
  return 0;
}

char *ip_addr_ntop(const ip_addr_t n, char *p, size_t size) {
  uint8_t *u8;

  u8 = (uint8_t *) &n;
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
  hdr = (struct ip_hdr *) data;
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

/* NOTE: must not be call after net_run() */
static struct ip_route *ip_route_add(ip_addr_t network, ip_addr_t netmask, ip_addr_t nexthop, struct ip_iface *iface) {
  struct ip_route *route;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  char addr3[IP_ADDR_STR_LEN];
  char addr4[IP_ADDR_STR_LEN];

  route = calloc(1, sizeof(*route));
  if (!route) {
    errorf("calloc() failure");
    return NULL;
  }

  route->network = network;
  route->netmask = netmask;
  route->nexthop = nexthop;
  route->iface = iface;
  route->next = routes;
  routes = route;

  infof("network=%s, netmask=%s, nexthop=%s, iface=%s dev=%s",
        ip_addr_ntop(route->network, addr1, sizeof(addr1)),
        ip_addr_ntop(route->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(route->nexthop, addr3, sizeof(addr3)),
        ip_addr_ntop(route->iface->unicast, addr4, sizeof(addr4)),
        NET_IFACE(iface)->dev->name
  );
  return route;
}

static struct ip_route *ip_route_lookup(ip_addr_t dst) {
  struct ip_route *route, *candidate = NULL;

  for (route = routes; route; route = route->next) {
    if ((dst & route->netmask) == route->network) {
      if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
        // longest match
        candidate = route;
      }
    }
  }
  return candidate;
}

/* NOTE: must not be call after net_run() */
int ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway) {
  ip_addr_t gw;
  if (ip_addr_pton(gateway, &gw) == -1) {
    errorf("ip_addr_pton() failure, addr=%s", gateway);
    return -1;
  }
  if (!ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface)) {
    errorf("ip_addr_pton() failure, addr=%s");
    return -1;
  }
  return 0;
}

struct ip_iface *ip_route_get_iface(ip_addr_t dst) {
  struct ip_route *route;

  route = ip_route_lookup(dst);
  if (!route) {
    return NULL;
  }
  return route->iface;
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask) {
  struct ip_iface *i;
  i = calloc(1, sizeof(*i));
  if (!i) {
    errorf("calloc() failure");
    return NULL;
  }

  NET_IFACE(i)->family = NET_IFACE_FAMILY_IP;

  ip_addr_t u;
  if (ip_addr_pton(unicast, &u) < 0) {
    errorf("failed to parse unicast address: %s\n", unicast);
    return NULL;
  }
  i->unicast = u;

  ip_addr_t n;
  if (ip_addr_pton(netmask, &n) < 0) {
    errorf("failed to parse netmask address: %s\n", netmask);
    return NULL;
  }
  i->netmask = n;

  // ホスト部のビットを全て1にする
  i->broadcast = u || ~n;

  return i;
}

/* NOTE: must not be call after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface) {
  if (net_device_add_iface(dev, NET_IFACE(iface)) < 0) {
    errorf("failed to register network interface to device");
    return -1;
  }

  iface->next = ifaces;
  ifaces = iface;

  char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN], addr3[IP_ADDR_STR_LEN];
  infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));

  return 0;
}

// ifacesからaddrを持つインターフェイスを探す
struct ip_iface *ip_iface_select(ip_addr_t addr) {
  for (struct ip_iface *i = ifaces; i; i = i->next) {
    if (i->unicast == addr) {
      return i;
    }
  }
  return NULL;
}

// IP input handler
static void ip_input(const uint8_t *data, size_t len, struct net_device *dev) {
  struct ip_hdr *hdr;

  // validate IP header
  if (len < IP_HDR_SIZE_MIN) {
    errorf("too short");
    return;
  }
  hdr = (struct ip_hdr *) data;
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
  if (cksum16((uint16_t *) data, hlen, 0) != 0) {
    errorf("checksum not match");
    return;
  }

  uint16_t offset = ntoh16(hdr->offset);
  // More Fragments or Fragment Offset is not zero
  if (offset & 0x2000 || offset & 0x1fff) {
    errorf("fragments does not support");
    return;
  }

  // devのIPインターフェイスを取得
  struct ip_iface *iface =
      (struct ip_iface *) net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
  if (!iface) {
    errorf("IP interface not found");
    return;
  }

  // IPアドレスの検証
  // a. インタフェースのIPアドレス
  // b. ブロードキャストIPアドレス（255.255.255.255）
  // c.インタフェースが属するサブネットのブロードキャストIPアドレス（xxx.xxx.xxx.255）
  if (hdr->dst != iface->unicast && hdr->dst != IP_ADDR_BROADCAST &&
      hdr->dst != iface->broadcast)
    return;

  char addr[IP_ADDR_STR_LEN];
  debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name,
         ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol,
         total);
  ip_dump(data, total);

  for (struct ip_protocol *p = protocols; p; p = p->next) {
    if (p->type == hdr->protocol) {
      p->handler((const uint8_t *) hdr + hlen, total - hlen, hdr->src, hdr->dst, iface);
      return;
    }
  }
  /* unsupported protocol */
}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data,
                            size_t len, ip_addr_t dst) {
  uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
  int ret;

  if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
    if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
      memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
    } else {
      ret = arp_resolve(NET_IFACE(iface), dst, hwaddr);
      if (ret != ARP_RESOLVE_FOUND) {
        return ret;
      }
    }
  }

  return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

// IPデータグラムの生成、デバイスに出力
static ssize_t ip_output_core(struct ip_iface *iface, uint8_t protocol,
                              const uint8_t *data, size_t len, ip_addr_t src,
                              ip_addr_t dst, ip_addr_t nexthop, uint16_t id, uint16_t offset) {
  uint8_t buf[IP_TOTAL_SIZE_MAX];
  struct ip_hdr *hdr = (struct ip_hdr *) buf;

  uint16_t hlen = IP_HDR_SIZE_MIN; // bytes
  hdr->vhl = IP_VERSION_IPV4 << 4 | hlen >> 2;  // Options無し
  hdr->tos = 0;
  uint16_t total = IP_HDR_SIZE_MIN + len;
  hdr->total = hton16(total);
  hdr->id = hton16(id);
  hdr->offset = hton16(offset);
  hdr->ttl = 255;
  hdr->protocol = protocol;
  hdr->src = src;
  hdr->dst = dst;
  hdr->sum = 0;
  hdr->sum = cksum16((uint16_t *) hdr, hlen, 0);

  buf[hlen] = *data;
  memcpy(&buf[hlen], data, len);

  char addr[IP_ADDR_STR_LEN];
  debugf("dev=%s, iface=%s, protocol=%u, len=%u",
         NET_IFACE(iface)->dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), protocol, total);
  ip_dump(buf, total);
  return ip_output_device(iface, buf, total, nexthop);
}

static uint16_t ip_generate_id(void) {
  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  static uint16_t id = 128;
  uint16_t ret;

  pthread_mutex_lock(&mutex);
  ret = id++;
  pthread_mutex_unlock(&mutex);
  return ret;
}

// output data to dst
// returns len
ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len,
                  ip_addr_t src, ip_addr_t dst) {
  struct ip_route *route;
  struct ip_iface *iface;
  char addr[IP_ADDR_STR_LEN];
  ip_addr_t nexthop;
  uint16_t id;

  if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST) {
    errorf("source address is required for broadcast address");
    return -1;
  }
  char addr2[IP_ADDR_STR_LEN];
  errorf("dst=%s", ip_addr_ntop(dst, addr2, sizeof(addr2)));

  route = ip_route_lookup(dst);
  if (!route) {
    errorf("no route to host, addr=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
    return -1;
  }
  iface = route->iface;
  if (src != IP_ADDR_ANY && src != iface->unicast) {
    char addr1[IP_ADDR_STR_LEN];
    errorf("iface->unicast=%s", ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)));
    errorf("unable to output with specified source address, addr=%s", ip_addr_ntop(src, addr, sizeof(addr)));
    return -1;
  }
  nexthop = (route->nexthop != IP_ADDR_ANY) ? route->nexthop : dst;
  if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
    errorf("too long, dev=%s, mtu=%u < %zu",
           NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
    return -1;
  }
  id = ip_generate_id();
  if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, nexthop, id, 0) == -1) {
    errorf("ip_output_core() failure");
    return -1;
  }
  return len;
}

/* NOTE: must not be call after net_run() */
int ip_protocol_register(uint8_t type,
                         void (*handler)(const uint8_t *data,
                                         size_t len,
                                         ip_addr_t src,
                                         ip_addr_t dst,
                                         struct ip_iface *iface)) {
  //プロトコルの重複を確認
  for (struct ip_protocol *p = protocols; p; p = p->next) {
    if (p->type == type) {
      errorf("protocol type %d is already registered", type);
      return -1;
    }
  }

  struct ip_protocol *p;
  p = calloc(1, sizeof(*p));
  if (!p) {
    errorf("calloc() failure");
    return -1;
  }

  p->type = type;
  p->handler = handler;
  p->next = protocols;
  protocols = p;

  infof("registered, type=%u", p->type);
  return 0;
}

int ip_init(void) {
  if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
    errorf("net_protocol_register() failure");
    return -1;
  }
  return 0;
}
