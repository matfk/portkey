import struct


def parse(payload):
    if len(payload) != 68:
        return None

    port = struct.unpack("!H", payload[0:2])[0]
    ttl = struct.unpack("!H", payload[2:4])[0]

    if port < 1 or port > 65535:
        return None

    if ttl == 0:
        return None

    return port, ttl, payload[4:68]
