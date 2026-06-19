from __future__ import annotations

import logging
import socket
import struct
from enum import IntEnum
from typing import NamedTuple

from protocol import (
    PKT_EXPECTED_LEN,
    PKT_FMT,
    PKT_PORT_MAX,
    PKT_PORT_MIN,
)

logger = logging.getLogger("portkey.packet")


class EtherType(IntEnum):
    IPV4 = 0x0800
    IPV6 = 0x86DD


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
IPV6_HDR_LEN = 40
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


def parse(payload: bytes) -> Packet | None:
    if len(payload) != PKT_EXPECTED_LEN:
        return None
    packet = Packet._make(PKT_FMT.unpack(payload))
    if not (PKT_PORT_MIN <= packet.port <= PKT_PORT_MAX):
        return None
    if packet.ttl == 0:
        return None
    return packet


def validate_frame(frame: bytes, addr: tuple) -> tuple[str, bytes] | None:
    if len(addr) >= ADDR_MIN_LEN and addr[ADDR_PKT_TYPE_IDX] == PACKET_OUTGOING:
        return None
    if len(frame) < ETH_HDR_LEN + IpOffset.MIN_HDR_LEN + UDP_HDR_LEN:
        return None

    ethertype_raw = frame[12:14]
    ethertype = struct.unpack("!H", ethertype_raw)[0]

    if ethertype == EtherType.IPV4:
        return parse_ipv4(frame)
    elif ethertype == EtherType.IPV6:
        return parse_ipv6(frame)
    return None


def parse_ipv4(frame: bytes) -> tuple[str, bytes] | None:
    ip_start = ETH_HDR_LEN

    if len(frame) < ip_start + IpOffset.MIN_HDR_LEN + UDP_HDR_LEN:
        return None
    if frame[ip_start + IpOffset.PROTO] != IpProto.UDP:
        return None

    ip_hl = (frame[ip_start] & IpOffset.IHL_MASK) * IpOffset.IHL_WORD

    frag_off_raw = frame[ip_start + 6 : ip_start + 8]
    frag_off = struct.unpack("!H", frag_off_raw)[0] & 0x1FFF
    if frag_off != 0:
        logger.debug("Skipping fragmented IPv4 packet")
        return None

    if len(frame) < ip_start + ip_hl + UDP_HDR_LEN:
        return None

    try:
        src_ip = socket.inet_ntoa(
            frame[ip_start + IpOffset.SRC_START : ip_start + IpOffset.SRC_END]
        )
    except OSError:
        logger.debug("Invalid IPv4 source address in frame")
        return None

    payload = frame[ip_start + ip_hl + UDP_HDR_LEN :]
    return src_ip, payload


def parse_ipv6(frame: bytes) -> tuple[str, bytes] | None:
    ip6_start = ETH_HDR_LEN

    if len(frame) < ip6_start + IPV6_HDR_LEN + UDP_HDR_LEN:
        return None

    next_header = frame[ip6_start + 6]
    current_offset = ip6_start + IPV6_HDR_LEN
    max_offset = len(frame) - UDP_HDR_LEN

    for _ in range(8):
        if next_header == IpProto.UDP:
            break
        if current_offset >= max_offset:
            return None
        next_header = frame[current_offset]
        hdr_ext_len = frame[current_offset + 1]
        current_offset += 8 + hdr_ext_len * 8
    else:
        logger.debug("IPv6 extension header chain too long or protocol not UDP")
        return None

    if current_offset + UDP_HDR_LEN > len(frame):
        return None

    try:
        src_ip = socket.inet_ntop(
            socket.AF_INET6, frame[ip6_start + 8 : ip6_start + 24]
        )
    except (OSError, ValueError):
        logger.debug("Invalid IPv6 source address in frame")
        return None

    payload = frame[current_offset + UDP_HDR_LEN :]
    return src_ip, payload


def verify_timestamp(timestamp: int, now: float, max_skew: int) -> bool:
    return abs(now - timestamp) <= max_skew
