#!/usr/bin/env python3

from __future__ import annotations

import atexit
import argparse
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

from nacl.exceptions import BadSignatureError

from protocol import PKT_BODY_LEN
from server.config import get_config, load_config, validate_only
from server.database import Database
from server.logging import setup_logging
from server.nftables import add as nft_add
from server.nftables import setup as nft_setup
from server.nftables import teardown as nft_teardown
from server.nonce import NonceSet
from server.packet import parse as parse_packet
from server.packet import validate_frame, verify_timestamp

logger = logging.getLogger("portkey.main")


def health_listener(sock_path: Path, stop_event: threading.Event) -> None:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock_path.unlink()
    except FileNotFoundError:
        pass

    sock.bind(str(sock_path))
    sock.listen(8)
    sock.settimeout(1.0)
    logger.info("Health socket listening on %s", sock_path)

    while not stop_event.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.sendall(b"OK\n")
        except OSError:
            pass
        finally:
            conn.close()

    sock.close()
    try:
        sock_path.unlink()
    except OSError:
        pass


def parse_args():
    parser = argparse.ArgumentParser(description="portkeyd. port-knocking daemon")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("portkey.toml"),
        help="Path to TOML configuration file (default: portkey.toml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and exit without starting the daemon",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.dry_run:
        ok = validate_only(args.config)
        sys.exit(0 if ok else 1)

    if os.geteuid() != 0:
        print("portkeyd: must run as root or CAP_NET_RAW + CAP_NET_ADMIN",
              file=sys.stderr)
        sys.exit(1)

    try:
        load_config(args.config)
    except Exception as exc:
        print(f"portkeyd: failed to load config: {exc}", file=sys.stderr)
        sys.exit(1)

    config = get_config()

    setup_logging(config)
    logger.info("portkeyd starting (pid=%d, config=%s)", os.getpid(), args.config)

    keys = config.verify_keys()
    if not keys:
        logger.warning("No valid keys loaded")

    nft_setup(binary=config.server.nft_binary)
    atexit.register(nft_teardown, binary=config.server.nft_binary)

    db = Database(config.server.database)
    atexit.register(db.close)

    nonces = NonceSet(db, ttl=config.server.max_clock_skew)
    nonces.start_cleanup_loop(interval=config.server.cleanup_interval)

    sock = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
    )
    atexit.register(sock.close)
    logger.info("Raw AF_PACKET socket open")

    config.server.health_socket.parent.mkdir(parents=True, exist_ok=True)

    stop_health = threading.Event()

    def shutdown_health():
        stop_health.set()

    health_thread = threading.Thread(
        target=health_listener,
        args=(config.server.health_socket, stop_health),
        daemon=True,
        name="health",
    )
    health_thread.start()
    atexit.register(shutdown_health)

    running = True

    def shutdown(signum, frame):
        nonlocal running
        logger.info("Received signal %d, shutting down", signum)
        running = False

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    max_skew = config.server.max_clock_skew
    max_ttl = config.server.max_ttl
    nft_bin = config.server.nft_binary

    knock_count = 0
    accept_count = 0

    logger.info("portkeyd listening (max_skew=%ds, max_ttl=%ds)", max_skew, max_ttl)

    try:
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
            port, ttl, timestamp, nonce, sig = parsed

            knock_count += 1

            if ttl > max_ttl:
                logger.debug("TTL %d exceeds max %d. capping", ttl, max_ttl)
                ttl = max_ttl

            now = time.time()
            if not verify_timestamp(timestamp, now, max_skew):
                logger.debug("Timestamp skew too large from %s (diff=%ds)",
                             src_ip, abs(now - timestamp))
                continue

            if nonces.seen(nonce):
                logger.debug("Replay detected from %s", src_ip)
                continue

            body = payload[:PKT_BODY_LEN]
            valid = False
            for key in keys:
                try:
                    key.verify(body, sig)
                    valid = True
                    break
                except BadSignatureError:
                    continue

            if not valid:
                logger.debug("Invalid signature from %s", src_ip)
                continue

            try:
                nft_add(src_ip, port, ttl, binary=nft_bin)
                accept_count += 1
            except Exception:
                logger.exception("nft add failed for %s:%d", src_ip, port)

    except KeyboardInterrupt:
        pass
    finally:
        shutdown_health()
        logger.info("portkeyd stopped")


if __name__ == "__main__":
    main()
