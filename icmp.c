#include <string.h>

#include "icmp.h"
#include "ip.h"
#include "util.h"

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

// Destination Unreachable Message, Time Exceeded Message, Source Quench Message
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |     Code      |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             unused                            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      Internet Header + 64 bits of Original Data Datagram      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Parameter Problem Message (second line)
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |    Pointer    |                   unused                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Redirect Message (second line)
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                 Gateway Internet Address                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Echo or Echo Reply Message (from second line)
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |        Sequence Number        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Data ...
//  +-+-+-+-+-
//
// Timestamp or Timestamp Reply Message (from second line)
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |        Sequence Number        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Originate Timestamp                                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Receive Timestamp                                         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Transmit Timestamp                                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Information Request or Information Reply Message
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |     Type      |      Code     |          Checksum             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Identifier          |        Sequence Number        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct icmp_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint32_t values;
};

struct icmp_echo {
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint16_t id;
  uint16_t seq;
};

static char *icmp_type_ntoa(uint8_t type) {
  switch (type) {
    case ICMP_TYPE_ECHOREPLY:return "EchoReply";
    case ICMP_TYPE_DEST_UNREACH:return "DestinationUnreachable";
    case ICMP_TYPE_SOURCE_QUENCH:return "SourceQuench";
    case ICMP_TYPE_REDIRECT:return "Redirect";
    case ICMP_TYPE_ECHO:return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:return "TimeExceeded";
    case ICMP_TYPE_PARAM_PROBLEM:return "ParameterProblem";
    case ICMP_TYPE_TIMESTAMP:return "Timestamp";
    case ICMP_TYPE_TIMESTAMPREPLY:return "TimestampReply";
    case ICMP_TYPE_INFO_REQUEST:return "InformationRequest";
    case ICMP_TYPE_INFO_REPLY:return "InformationReply";
  }
  return "Unknown";
}

static void icmp_dump(const uint8_t *data, size_t len) {
  struct icmp_hdr *hdr;
  struct icmp_echo *echo;

  flockfile(stderr);
  hdr = (struct icmp_hdr *) data;
  fprintf(stderr, "       type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
  fprintf(stderr, "       code: %u\n", hdr->code);
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
  switch (hdr->type) {
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:echo = (struct icmp_echo *) hdr;
      fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
      fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
      break;
    default:fprintf(stderr, "     values: 0x%08x\n", ntoh32(hdr->values));
      break;
  }
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

void icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface) {
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  struct icmp_hdr *hdr;

  if (len < ICMP_HDR_SIZE) {
    errorf("input data is too short: %d bytes", len);
    return;
  }

  // checksum
  uint16_t sum = cksum16((uint16_t *) data, len, 0);
  if (sum != 0) {
    errorf("checksum not match: 0x%02x", sum);
    return;
  }

  debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
  icmp_dump(data, len);

  hdr = (struct icmp_hdr *) data;
  switch (hdr->type) {
    case ICMP_TYPE_ECHO:
      if (icmp_output(ICMP_TYPE_ECHOREPLY,
                      hdr->code,
                      hdr->values,
                      data + ICMP_HDR_SIZE,
                      len - ICMP_HDR_SIZE,
                      iface->unicast,
                      src)
          < 0) {
        errorf("icmp_output() failure");
        return;
      }
      break;
    default: /* ignore */
      break;
  }
}

int icmp_output(uint8_t type,
                uint8_t code,
                uint32_t values,
                const uint8_t *data,
                size_t len,
                ip_addr_t src,
                ip_addr_t dst) {
  uint8_t buf[ICMP_BUFSIZ];
  struct icmp_hdr *hdr;
  size_t msg_len;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];

  hdr = (struct icmp_hdr *) buf;
  hdr->type = type;
  hdr->code = code;
  hdr->sum = 0;
  hdr->values = values;
  memcpy(hdr + 1, data, len);
  msg_len = sizeof(*hdr) + len;
  hdr->sum = cksum16((uint16_t *) hdr, msg_len, 0);
  debugf("%s => %s, type=%s(%u), len=%zu",
         ip_addr_ntop(src, addr1, sizeof(addr1)),
         ip_addr_ntop(dst, addr2, sizeof(addr2)),
         icmp_type_ntoa(hdr->type), hdr->type, msg_len);
  icmp_dump((uint8_t *) hdr, msg_len);
  return ip_output(IP_PROTOCOL_ICMP, (uint8_t *) hdr, msg_len, src, dst);
}

int icmp_init() {
  if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) < 0) {
    errorf("ip_protocol_register() failure");
    return -1;
  }
  return 0;
}

