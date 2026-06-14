import socket
import struct

ETH_HDR_LEN = 14
ETHERTYPE_IPV4 = b"\x08\x00"

IP_PROTO_OFFSET = 9
IP_SRC_OFFSET = 12
IP_SRC_END = 16
IP_IHL_MASK = 0x0F
IP_IHL_WORD = 4
IP_PROTO_UDP = 17
MIN_IP_HDR_LEN = 20

UDP_HDR_LEN = 8

ADDR_PKT_TYPE_IDX = 2
PACKET_OUTGOING = 4
ADDR_MIN_LEN = 3

PKT_PORT_SIZE = 2
PKT_TTL_SIZE = 2
PKT_SIG_SIZE = 64

PKT_PORT_START = 0
PKT_PORT_END = PKT_PORT_START + PKT_PORT_SIZE
PKT_TTL_START = PKT_PORT_END
PKT_TTL_END = PKT_TTL_START + PKT_TTL_SIZE
PKT_SIG_START = PKT_TTL_END
PKT_SIG_END = PKT_SIG_START + PKT_SIG_SIZE
PKT_EXPECTED_LEN = PKT_SIG_END
PKT_PORT_MIN = 1
PKT_PORT_MAX = 65535


def parse(payload):
    if len(payload) != PKT_EXPECTED_LEN:
        return None

    port = struct.unpack("!H", payload[PKT_PORT_START:PKT_PORT_END])[0]
    ttl = struct.unpack("!H", payload[PKT_TTL_START:PKT_TTL_END])[0]

    if port < PKT_PORT_MIN or port > PKT_PORT_MAX:
        return None

    if ttl == 0:
        return None

    return port, ttl, payload[PKT_SIG_START:PKT_SIG_END]


def validate_frame(frame, addr):
    if len(addr) >= ADDR_MIN_LEN and addr[ADDR_PKT_TYPE_IDX] == PACKET_OUTGOING:
        return None

    if len(frame) < ETH_HDR_LEN + MIN_IP_HDR_LEN + UDP_HDR_LEN:
        return None

    if frame[12:14] != ETHERTYPE_IPV4:
        return None

    ip_start = ETH_HDR_LEN
    if frame[ip_start + IP_PROTO_OFFSET] != IP_PROTO_UDP:
        return None

    ip_hl = (frame[ip_start] & IP_IHL_MASK) * IP_IHL_WORD

    if len(frame) < ip_start + ip_hl + UDP_HDR_LEN:
        return None

    src_ip = socket.inet_ntoa(frame[ip_start + IP_SRC_OFFSET : ip_start + IP_SRC_END])
    payload = frame[ip_start + ip_hl + UDP_HDR_LEN :]

    return src_ip, payload
