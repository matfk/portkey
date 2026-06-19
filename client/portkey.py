#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from pathlib import Path

from nacl.signing import SigningKey

from protocol import PKT_BODY_FMT


def knock(
    host: str,
    port: int,
    ttl: int,
    key_path: Path,
    *,
    retries: int = 3,
    retry_delay: float = 0.5,
) -> None:
    key = SigningKey(key_path.read_bytes())

    timestamp = int(time.time())
    nonce = os.urandom(16)
    body = PKT_BODY_FMT.pack(port, ttl, timestamp, nonce)
    sig = key.sign(body).signature
    payload = body + sig

    for attempt in range(1, retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(payload, (host, port))
            print(f"Knock sent to {host}:{port} (ttl={ttl}s)")
            return
        except OSError as exc:
            if attempt < retries:
                print(f"Attempt {attempt}/{retries} failed: {exc}; retrying in {retry_delay}s",
                      file=sys.stderr)
                time.sleep(retry_delay)
            else:
                print(f"All {retries} attempts failed", file=sys.stderr)
                raise


def main() -> None:
    p = argparse.ArgumentParser(description="Send a signed UDP knock.")
    p.add_argument("host", help="Target host")
    p.add_argument("port", type=int, help="TCP port to open")
    p.add_argument(
        "--ttl", type=int, default=60, help="Seconds to keep open (default: 60)"
    )
    p.add_argument(
        "--key", default="~/.config/portkey/key", help="Ed25519 private key path"
    )
    p.add_argument(
        "--retries", type=int, default=3, help="Number of send attempts (default: 3)"
    )
    p.add_argument(
        "--retry-delay",
        type=float,
        default=0.5,
        help="Delay between retries in seconds (default: 0.5)",
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
        knock(
            args.host,
            args.port,
            args.ttl,
            key_path,
            retries=args.retries,
            retry_delay=args.retry_delay,
        )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
