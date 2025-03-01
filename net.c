#include "net.h"

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "ip.h"
#include "util.h"
#include "icmp.h"
#include "arp.h"
#include "udp.h"

struct net_protocol {
  struct net_protocol *next;
  uint16_t type;
  pthread_mutex_t
      mutex; /* mutex for input queue (操作時はmutexによる保護が必要) */
  struct queue_head queue; /* input queue */
  void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

/* NOTE: the data follows immediately after the structure */
struct net_protocol_queue_entry {
  struct net_device *dev;
  size_t len;
};

struct net_timer {
  struct net_timer *next;
  struct timeval interval;
  struct timeval last;
  void (*handler)(void);
};

struct net_interrupt_ctx {
  struct net_interrupt_ctx *prev;
  struct net_interrupt_ctx *next;
  int occurred;
};

static struct {
  struct net_interrupt_ctx *head;
  pthread_mutex_t mutex;
} interrupts;

static volatile sig_atomic_t interrupted;

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices;
// ネットワーク層のプロトコルリスト
static struct net_protocol *protocols;
static struct net_timer *timers;

struct net_device *net_device_alloc(void) {
  struct net_device *dev;

  dev = calloc(1, sizeof(*dev));
  if (!dev) {
    errorf("calloc() failure");
    return NULL;
  }
  return dev;
}

// デバイスのindex, nameを設定して、devicesに追加
int net_device_register(struct net_device *dev) {
  // MEMO: staticをつけると、関数が終了しても消滅せず、値を残すことができる
  // indexのスコープはこの関数内
  static unsigned int index = 0;

  dev->index = index++;
  snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
  // devicesの先頭にdevを追加
  dev->next = devices;
  devices = dev;
  infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
  return 0;
}

static int net_device_open(struct net_device *dev) {
  if (NET_DEVICE_IS_UP(dev)) {
    errorf("already opened, dev=%s", dev->name);
    return -1;
  }
  if (dev->ops->open) {
    if (dev->ops->open(dev) == -1) {
      errorf("failure, dev=%s", dev->name);
      return -1;
    }
  }
  dev->flags |= NET_DEVICE_FLAG_UP;
  infof("dev=%s, state-%s", dev->name, NET_DEVICE_STATE(dev));
  return 0;
}

static int net_device_close(struct net_device *dev) {
  if (!NET_DEVICE_IS_UP(dev)) {
    errorf("not opened, dev=%s", dev->name);
    return -1;
  }
  if (dev->ops->close) {
    if (dev->ops->close(dev) == -1) {
      errorf("failure, dev=%s", dev->name);
      return -1;
    }
  }
  dev->flags &= ~NET_DEVICE_FLAG_UP;
  infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
  return 0;
}

/* NOTE: must not be call after net_run() */
int net_device_add_iface(struct net_device *dev, struct net_iface *iface) {
  // 1つのnet_device内のnet_ifaceのfamilyは重複しない
  for (struct net_iface *i = dev->ifaces; i; i = i->next) {
    if (i->family == iface->family) {
      errorf("already exists, dev=%s, family=%d", dev->name, i->family);
      return -1;
    }
  }

  iface->next = dev->ifaces;
  dev->ifaces = iface;
  iface->dev = dev;

  return 0;
}

// familyに合致するifaceを返す
struct net_iface *net_device_get_iface(struct net_device *dev, int family) {
  for (struct net_iface *i = dev->ifaces; i; i = i->next) {
    if (i->family == family) {
      return i;
    }
  }
  return NULL;
}

// デバイスへの出力
int net_device_output(struct net_device *dev, uint16_t type,
                      const uint8_t *data, size_t len, const void *dst) {
  if (!NET_DEVICE_IS_UP(dev)) {
    errorf("not opened, dev=%s", dev->name);
    return -1;
  }
  // デバイスのMTUを超えるデータは送信できない
  if (len > dev->mtu) {
    errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
    return -1;
  }
  debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
  debugdump(data, len);
  if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
    errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
    return -1;
  }
  return 0;
}

// デバイスからの入力(デバイスドライバから呼び出される)
int net_input_handler(uint16_t type, const uint8_t *data, size_t len,
                      struct net_device *dev) {
  struct net_protocol *proto;
  struct net_protocol_queue_entry *entry;
  // queue length
  unsigned int num;

  for (proto = protocols; proto; proto = proto->next) {
    if (proto->type == type) {
      // protoの受信キューに格納
      entry = calloc(1, sizeof(*entry) + len);
      if (!entry) {
        errorf("calloc() failure");
        return -1;
      }
      entry->dev = dev;
      entry->len = len;
      memcpy(entry + 1, data, len);
      pthread_mutex_lock(&proto->mutex);
      if (!queue_push(&proto->queue, entry)) {
        pthread_mutex_unlock(&proto->mutex);
        errorf("queue_push() failure");
        free(entry);
        return -1;
      }

      num = proto->queue.num;
      pthread_mutex_unlock(&proto->mutex);

      debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zd", num,
             dev->name, type, len);
      debugdump(data, len);
      return 0;
    }
  }
  /* unsupported protocol */

  return 0;
}

/* NOTE: must not be call after net_run() */
int net_protocol_register(uint16_t type,
                          void (*handler)(const uint8_t *data, size_t len,
                                          struct net_device *dev)) {
  struct net_protocol *proto;

  // 重複の確認
  for (proto = protocols; proto; proto = proto->next) {
    if (type == proto->type) {
      errorf("already registered, type=0x%04x", type);
      return -1;
    }
  }

  proto = calloc(1, sizeof(*proto));
  if (!proto) {
    errorf("calloc failure");
    return -1;
  }
  proto->type = type;
  pthread_mutex_init(&proto->mutex, NULL);
  proto->handler = handler;
  proto->next = protocols;
  protocols = proto;
  infof("registered, type=0x%04x", type);
  return 0;
}

/* NOTE: must not be call after net_run() */
int net_timer_register(struct timeval interval, void (*handler)(void)) {
  struct net_timer *timer;

  timer = calloc(1, sizeof(*timer));
  if (!timer) {
    errorf("calloc() failure");
    return -1;
  }
  timer->interval = interval;
  gettimeofday(&timer->last, NULL);
  timer->handler = handler;
  timer->next = timers;
  timers = timer;

  infof("registered: interval={%d, %d}", interval.tv_sec, interval.tv_usec);
  return 0;
}

#define NET_THREAD_SLEEP_TIME 100 /* micro seconds */

// ポーリングのためのスレッド
// 本来kernelではソフトウェア割り込みによって処理する
static pthread_t thread;
static volatile sig_atomic_t terminate;

static void *net_thread(void *arg) {
  unsigned int count, num;
  struct net_device *dev;
  struct net_protocol *proto;
  struct net_protocol_queue_entry *entry;
  struct net_timer *timer;
  struct timeval now, diff;
  struct net_interrupt_ctx *ctx;

  while (!terminate) {
    count = 0;
    // デバイスにパケットが到着しているか確認
    for (dev = devices; dev; dev = dev->next) {
      if (NET_DEVICE_IS_UP(dev)) {
        if (dev->ops->poll) {
          if (dev->ops->poll(dev) != -1) {
            count++;
          }
        }
      }
    }
    // プロトコルの受信キューを確認
    for (proto = protocols; proto; proto = proto->next) {
      pthread_mutex_lock(&proto->mutex);
      entry = queue_pop(&proto->queue);
      num = proto->queue.num;
      pthread_mutex_unlock(&proto->mutex);
      if (entry) {
        debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zd", num,
               entry->dev->name, proto->type, entry->len);
        debugdump((uint8_t * )(entry + 1), entry->len);
        proto->handler((uint8_t * )(entry + 1), entry->len, entry->dev);
        free(entry);
        count++;
      }
    }
    for (timer = timers; timer; timer = timer->next) {
      gettimeofday(&now, NULL);
      timersub(&now, &timer->last, &diff);
      if (timercmp(&timer->interval, &diff, <) != 0) { /* true (!0) or false (0) */
        timer->handler();
        gettimeofday(&timer->last, NULL);
      }
    }

    if (interrupted) {
      debugf("interrupt occurred");
      pthread_mutex_lock(&interrupts.mutex);
      for (ctx = interrupts.head; ctx; ctx = ctx->next) {
        ctx->occurred = 1;
      }
      pthread_mutex_unlock(&interrupts.mutex);
      interrupted = 0;
    }

    // 何も処理が行われなかったとき
    if (!count) {
      usleep(NET_THREAD_SLEEP_TIME);
    }
  }
  return NULL;
}

// プロトコルスタックの起動(登録済みの全てのデバイスをオープン)
int net_run(void) {
  struct net_device *dev;
  int err;

  debugf("open all devices...");
  for (dev = devices; dev; dev = dev->next) {
    net_device_open(dev);
  }
  debugf("running...");

  debugf("create background thread...");
  err = pthread_create(&thread, NULL, net_thread, NULL);
  if (err) {
    errorf("pthread_create() failure, err=%d", err);
    return -1;
  }

  return 0;
}

// プロトコルスタックの停止(登録済みの全てのデバイスをクローズ)
void net_shutdown(void) {
  struct net_device *dev;

  int err;

  debugf("terminate background thread...");
  terminate = 1;
  err = pthread_join(thread, NULL);
  if (err) {
    errorf("pthread_join() failure, err=%d", err);
    return;
  }

  debugf("close all devices...");
  for (dev = devices; dev; dev = dev->next) {
    net_device_close(dev);
  }
  debugf("shutdown");
}

void net_interrupt(void) {
  interrupted = 1;
}

struct net_interrupt_ctx *net_interrupt_subscribe(void) {
  struct net_interrupt_ctx *ctx;

  ctx = calloc(1, sizeof(struct net_interrupt_ctx));
  if (!ctx) {
    errorf("calloc() failure");
    return NULL;
  }
  pthread_mutex_lock(&interrupts.mutex);
  if (interrupts.head) {
    ctx->next = interrupts.head;
    interrupts.head->prev = ctx;
  }
  interrupts.head = ctx;
  pthread_mutex_unlock(&interrupts.mutex);
  return ctx;
}

int net_interrupt_occurred(struct net_interrupt_ctx *ctx) {
  int occurred;

  pthread_mutex_lock(&interrupts.mutex);
  occurred = ctx->occurred;
  pthread_mutex_unlock(&interrupts.mutex);
  return occurred;
}

int net_interrupt_unsubscribe(struct net_interrupt_ctx *ctx) {
  pthread_mutex_lock(&interrupts.mutex);
  if (interrupts.head == ctx) {
    interrupts.head = ctx->next;
  }
  if (ctx->next) {
    ctx->next->prev = ctx->prev;
  }
  if (ctx->prev) {
    ctx->prev->next = ctx->next;
  }
  pthread_mutex_unlock(&interrupts.mutex);
  return 0;
}

int net_init(void) {
  if (ip_init() == -1) {
    errorf("ip_init() failure");
    return -1;
  }

  if (icmp_init() == -1) {
    errorf("icmp_init() failure");
    return -1;
  }

  if (arp_init() == -1) {
    errorf("arp_init() failure");
    return -1;
  }

  if (udp_init() == -1) {
    errorf("udp_init() failure");
    return -1;
  }

  return 0;
}
