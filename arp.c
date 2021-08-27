#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_CACHE_SIZE 32

#define ARP_CACHE_STATE_FREE       0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED   2
#define ARP_CACHE_STATE_STATIC     3

struct arp_hdr {
  uint16_t hrd;
  uint16_t pro;
  uint8_t hln;
  uint8_t pln;
  uint16_t op;
};

struct arp_ether {
  struct arp_hdr hdr;
  uint8_t sha[ETHER_ADDR_LEN]; /* Sender Hardware Address */
  uint8_t spa[IP_ADDR_LEN]; /* Sender Protocol Address */
  uint8_t tha[ETHER_ADDR_LEN]; /* Target Hardware Address */
  uint8_t tpa[IP_ADDR_LEN]; /* Target Protocol Address */
};

struct arp_cache {
  unsigned char state;
  ip_addr_t pa;
  uint8_t ha[ETHER_ADDR_LEN];
  struct timeval timestamp;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE];

static char *arp_opcode_ntoa(uint16_t opcode) {
  switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:return "Request";
    case ARP_OP_REPLY:return "Reply";
  }
  return "Unknown";
}

static void arp_dump(const uint8_t *data, size_t len) {
  struct arp_ether *message;
  ip_addr_t spa, tpa;
  char addr[128];

  message = (struct arp_ether *) data;
  flockfile(stderr);
  fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
  fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
  fprintf(stderr, "        hln: %u\n", message->hdr.hln);
  fprintf(stderr, "        pln: %u\n", message->hdr.pln);
  fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
  fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
  memcpy(&spa, message->spa, sizeof(spa));
  fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
  fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
  memcpy(&tpa, message->tpa, sizeof(tpa));
  fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

/*
 * ARP Cache
 *
 * NOTE: ARP Cache functions must be called after mutex locked
 */

static struct arp_cache *arp_cache_alloc(void) {

}

static struct arp_cache *arp_cache_select(ip_addr_t pa) {

}

static struct arp_cache *arp_cache_update(ip_addr_t pa, const uint8_t *ha) {

}

static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha) {

}

static void arp_cache_delete(struct arp_cache *cache) {

}

static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst) {
  struct arp_ether reply;

  reply.hdr.hrd = hton16(ARP_HRD_ETHER);
  reply.hdr.pro = hton16(ARP_PRO_IP);
  reply.hdr.hln = ETHER_ADDR_LEN;
  reply.hdr.pln = IP_ADDR_LEN;
  reply.hdr.op = hton16(ARP_OP_REPLY);
  memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
  memcpy(reply.spa, &((struct ip_iface *) iface)->unicast, IP_ADDR_LEN);
  memcpy(reply.tha, tha, ETHER_ADDR_LEN);
  memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

  debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
  arp_dump((uint8_t *) &reply, sizeof(reply));
  return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *) &reply, sizeof(reply), dst);
}

static void arp_input(const uint8_t *data, size_t len, struct net_device *dev) {
  struct arp_ether *msg;
  ip_addr_t spa, tpa;
  struct net_iface *iface;

  if (len < sizeof(*msg)) {
    errorf("too short");
    return;
  }

  msg = (struct arp_ether *) data;
  if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
    debugf("unknown hardware address type: type=0x%04x, len=%d", msg->hdr.hrd, msg->hdr.hln);
    return;
  }

  if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
    debugf("unknown protocol address type: type=0x%04x, len=%d", msg->hdr.hrd, msg->hdr.hln);
    return;
  }

  debugf("dev=%s, len=%zu", dev->name, len);
  arp_dump(data, len);

  memcpy(&spa, msg->spa, sizeof(spa));
  memcpy(&tpa, msg->tpa, sizeof(tpa));
  iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
  if (iface && ((struct ip_iface *) iface)->unicast == tpa) {
    if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
      if (arp_reply(iface, msg->sha, spa, msg->sha) == -1) {
        errorf("arp_reply() failure");
        return;
      }
    }
    // TODO: ARP_OP_REPLY
    warnf("Unknown arp operation code: 0x%04x", ntoh16(msg->hdr.op));
  }
}

int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha) {

}

int arp_init(void) {
  if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
    errorf("net_protocol_register() failure");
    return -1;
  }
  return 0;
}