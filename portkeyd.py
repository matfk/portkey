#!/usr/bin/env python3
import os
import signal
import socket
import struct
import subprocess
import sys
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


def load_dotenv(path=".env"):
    env_file = Path(path)
    if not env_file.is_file():
        env_file = Path(__file__).resolve().parent / ".env"
    if not env_file.is_file():
        return
    for raw in env_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        os.environ.setdefault(key, val)


def nft_setup():
    subprocess.run(["nft", "delete", "table", "inet", "portkey"], capture_output=True)
    subprocess.run(
        ["nft", "-f", "/dev/stdin"],
        input=b"""
			table inet portkey {
			    set allowed {
			        type ipv4_addr . inet_service
			        flags dynamic,timeout
			        timeout 1s
			    }
			    chain input {
			        type filter hook input priority filter; policy accept;
			        ip saddr . tcp dport @allowed accept
			    }
			}
			""",
        check=True,
    )


def nft_teardown():
    subprocess.run(["nft", "delete", "table", "inet", "portkey"], capture_output=True)


def nft_add(address, port, ttl):
    subprocess.run(
        [
            "nft",
            "add",
            "element",
            "inet",
            "portkey",
            "allowed",
            f"{{ {address} . {port} timeout {ttl}s }}",
        ],
        capture_output=True,
        check=True,
    )


def parse_packet(payload):
    if len(payload) != 68:
        return None
    port = struct.unpack("!H", payload[0:2])[0]
    ttl = struct.unpack("!H", payload[2:4])[0]
    if port < 1 or port > 65535:
        return None
    if ttl == 0:
        return None
    return port, ttl, payload[4:68]


def main():
    load_dotenv()

    pubkey_hex = os.environ.get("PORTKEY_PUBKEY")
    if not pubkey_hex:
        print("PORTKEY_PUBKEY not set", file=sys.stderr)
        sys.exit(1)
    try:
        pubkey = VerifyKey(bytes.fromhex(pubkey_hex))
    except Exception as e:
        print(f"Invalid PORTKEY_PUBKEY: {e}", file=sys.stderr)
        sys.exit(1)

    nft_setup()

    running = True

    def shutdown(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    print("portkeyd: listening ...", file=sys.stderr)

    while running:
        try:
            frame, addr = sock.recvfrom(65535)
        except (OSError, InterruptedError):
            if not running:
                break
            continue

        # addr = (ifindex, protocol, pkttype, hatype, hwaddr)
        if len(addr) >= 3 and addr[2] == 4:
            continue

        # raw ethernet frame checks
        if len(frame) < 14 + 20 + 8:
            continue
        if frame[12:14] != b"\x08\x00":  # check ipv4
            continue
        if frame[14 + 9] != 17:  # check udp
            continue

        ip_hl = (frame[14] & 0x0F) * 4
        if len(frame) < 14 + ip_hl + 8:
            continue

        src_ip = ".".join(str(b) for b in frame[14 + 12 : 14 + 16])
        payload = frame[14 + ip_hl + 8 :]

        parsed = parse_packet(payload)
        if parsed is None:
            continue

        port, ttl, sig = parsed
        try:
            pubkey.verify(payload[:4], sig)
        except BadSignatureError:
            continue

        try:
            nft_add(src_ip, port, ttl)
            print(f"open {src_ip}:{port} for {ttl}s")
        except subprocess.CalledProcessError as e:
            print(f"nft error: {e.stderr.decode().strip()}", file=sys.stderr)

    sock.close()
    nft_teardown()
    print("portkeyd: shut down", file=sys.stderr)


if __name__ == "__main__":
    main()
