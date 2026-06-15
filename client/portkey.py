#!/usr/bin/env python3
import argparse
import os
import socket
import sys
import time
from pathlib import Path

from nacl.signing import SigningKey

from protocol import PKT_BODY_FMT


def knock(host, port, ttl, key_path):
    key = SigningKey(Path(key_path).read_bytes())

    timestamp = time.time()
    nonce = os.urandom(16)
    body = PKT_BODY_FMT.pack(port, ttl, int(timestamp), nonce)
    sig = key.sign(body).signature

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(body + sig, (host, port))


def main():
    p = argparse.ArgumentParser(description="Send a signed UDP knock.")
    p.add_argument("host", help="Target host")
    p.add_argument("port", type=int, help="TCP port to open")
    p.add_argument(
        "--ttl", type=int, default=60, help="Seconds to keep open (default: 60)"
    )
    p.add_argument(
        "--key", default="~/.config/portkey/key", help="Ed25519 private key path"
    )
    args = p.parse_args()

    if not 1 <= args.port <= 65535:
        print("error: port must be 1–65535", file=sys.stderr)
        sys.exit(1)

    if args.ttl < 1:
        print("error: ttl must be >= 1", file=sys.stderr)
        sys.exit(1)

    key_path = Path(args.key).expanduser()
    if not key_path.exists():
        print(f"error: key not found: {key_path}", file=sys.stderr)
        sys.exit(1)

    try:
        knock(args.host, args.port, args.ttl, key_path)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
