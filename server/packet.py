import socket
from enum import IntEnum
from typing import NamedTuple

from protocol import (
    PKT_EXPECTED_LEN,
    PKT_FMT,
    PKT_PORT_MAX,
    PKT_PORT_MIN,
)


class EtherType(IntEnum):
    IPV4 = 0x0800


class IpProto(IntEnum):
    UDP = 17


class IpOffset:
    PROTO = 9
    SRC_START = 12
    SRC_END = 16
    IHL_MASK = 0x0F
    IHL_WORD = 4
    MIN_HDR_LEN = 20


ETH_HDR_LEN = 14
UDP_HDR_LEN = 8

ADDR_PKT_TYPE_IDX = 2
PACKET_OUTGOING = 4
ADDR_MIN_LEN = 3


class Packet(NamedTuple):
    port: int
    ttl: int
    timestamp: int
    nonce: bytes
    signature: bytes


def parse(payload):
    if len(payload) != PKT_EXPECTED_LEN:
        return None

    packet = Packet._make(PKT_FMT.unpack(payload))

    if not (PKT_PORT_MIN <= packet.port <= PKT_PORT_MAX):
        return None

    if packet.ttl == 0:
        return None

    return packet


def validate_frame(frame, addr):
    if len(addr) >= ADDR_MIN_LEN and addr[ADDR_PKT_TYPE_IDX] == PACKET_OUTGOING:
        return None

    if len(frame) < ETH_HDR_LEN + IpOffset.MIN_HDR_LEN + UDP_HDR_LEN:
        return None

    if frame[12:14] != EtherType.IPV4.to_bytes(2, "big"):
        return None

    ip_start = ETH_HDR_LEN
    if frame[ip_start + IpOffset.PROTO] != IpProto.UDP:
        return None

    ip_hl = (frame[ip_start] & IpOffset.IHL_MASK) * IpOffset.IHL_WORD

    if len(frame) < ip_start + ip_hl + UDP_HDR_LEN:
        return None

    src_ip = socket.inet_ntoa(
        frame[ip_start + IpOffset.SRC_START : ip_start + IpOffset.SRC_END]
    )
    payload = frame[ip_start + ip_hl + UDP_HDR_LEN :]

    return src_ip, payload


def verify_timestamp(timestamp, now, max_skew):
    return abs(now - timestamp) <= max_skew
