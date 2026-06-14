#!/usr/bin/env python3
import signal
import socket
import subprocess
import sys

from nacl.exceptions import BadSignatureError

from server.config import load_dotenv, load_pubkey
from server.nftables import add as nft_add
from server.nftables import setup as nft_setup
from server.nftables import teardown as nft_teardown
from server.packet import parse as parse_packet
from server.packet import validate_frame


def main():
    load_dotenv()
    pubkey = load_pubkey()
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

        result = validate_frame(frame, addr)
        if result is None:
            continue

        src_ip, payload = result

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
