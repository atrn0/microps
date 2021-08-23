#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "driver/loopback.h"
#include "ip.h"
#include "net.h"
#include "test.h"
#include "util.h"

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
  // シグナルハンドラの設定(Ctrl+Cを押したときにon_signalが呼び出される)
  signal(SIGINT, on_signal);

  if (setup() < 0) {
    errorf("setup() failure");
    return -1;
  }

  ip_addr_t src, dst;
  ip_addr_pton(LOOPBACK_IP_ADDR, &src);
  dst = src;

  size_t offset = IP_HDR_SIZE_MIN;

  while (!terminate) {
    if (ip_output(0x01,
                  test_data + offset /* IPヘッダ以降 */,
                  sizeof(test_data) - offset,
                  src, dst) < 0) {
      errorf("ip_output() failure");
      break;
    }
    sleep(1);
  }
  cleanup();
  return 0;
}
