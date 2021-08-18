#include "net.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ip.h"
#include "util.h"

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

static struct net_device *devices;
// ネットワーク層のプロトコルリスト
static struct net_protocol *protocols;

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

// プロトコルスタックの起動(登録済みの全てのデバイスをオープン)
int net_run(void) {
  struct net_device *dev;

  debugf("open all devices...");
  for (dev = devices; dev; dev = dev->next) {
    net_device_open(dev);
  }
  debugf("running...");
  return 0;
}

// プロトコルスタックの停止(登録済みの全てのデバイスをクローズ)
void net_shutdown(void) {
  struct net_device *dev;

  debugf("close all devices...");
  for (dev = devices; dev; dev = dev->next) {
    net_device_close(dev);
  }
  debugf("shutdown");
}

int net_init(void) {
  if (ip_init() == -1) {
    errorf("ip_init() failure");
    return -1;
  }
  return 0;
}
