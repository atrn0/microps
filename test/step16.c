#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <icmp.h>

#include "driver/loopback.h"
#include "ip.h"
#include "net.h"
#include "test.h"
#include "util.h"
#include "driver/ether_tap.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
  (void) s;
  terminate = 1;
}

static int setup() {
  if (net_init() == -1) {
    errorf("net_init() failure");
    return -1;
  }

  struct net_device *dev = loopback_init();
  if (!dev) {
    errorf("loopback_init() failure");
    return -1;
  }

  struct ip_iface *iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
  if (!iface) {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if (ip_iface_register(dev, iface) == -1) {
    errorf("ip_iface_register() failure");
    return -1;
  }

  struct net_device *dev2 = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
  if (!dev2) {
    errorf("ether_tap_init() failure");
    return -1;
  }
  struct ip_iface *iface2 = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
  if (!iface2) {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if (ip_iface_register(dev2, iface2) == -1) {
    errorf("ip_iface_register() failure");
    return -1;
  }

  if (ip_route_set_default_gateway(iface2, DEFAULT_GATEWAY) == -1) {
    errorf("ip_route_set_default_gateway() failure");
    return -1;
  }

  if (net_run() == -1) {
    errorf("net_run() failure");
    return -1;
  }

  return 0;
}

static void cleanup() {
  net_shutdown();
}

int main(int argc, char *argv[]) {
  ip_addr_t src, dst;
  uint16_t id, seq = 0;
  size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

  signal(SIGINT, on_signal);
  if (setup() == -1) {
    errorf("setup() failure");
    return -1;
  }
  ip_addr_pton("192.0.2.2", &src);
  ip_addr_pton("8.8.8.8", &dst);
  id = getpid() % UINT16_MAX;

  while (!terminate) {
    if (icmp_output(ICMP_TYPE_ECHO,
                    0,
                    hton32(id << 16 | ++seq),
                    test_data + offset,
                    sizeof(test_data) - offset,
                    src,
                    dst) == -1) {
      errorf("icmp_output() failure");
      break;
    }
    sleep(10);
  }
  cleanup();
}
