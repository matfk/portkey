#!/usr/bin/env python
import os
import signal
import socket
import subprocess
import sys
import time

from nacl.exceptions import BadSignatureError
from pathlib import Path

from protocol import PKT_BODY_LEN
from server.database import Database
from server.nftables import add as nft_add
from server.nftables import setup as nft_setup
from server.nftables import teardown as nft_teardown
from server.nonce import NonceSet
from server.packet import parse as parse_packet
from server.packet import validate_frame, verify_timestamp
from server.config import Config

MAX_CLOCK_SKEW = 60


def main():
	if os.geteuid() != 0:
		print("portkeyd: must run as root", file=sys.stderr)
		sys.exit(1)

	nft_setup()


	config = Config.load(Path("portkey.toml"))
	keys = config.verify_keys()
	db = Database(config.server.database)
	nonces = NonceSet(db, ttl=config.server.max_clock_skew)
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

		port, ttl, timestamp, nonce, sig = parsed

		now = time.time()
		if not verify_timestamp(timestamp, now, MAX_CLOCK_SKEW):
			continue

		if nonces.seen(nonce):
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
			continue

		try:
			nft_add(src_ip, port, ttl)
			print(f"open {src_ip}:{port} for {ttl}s")
		except subprocess.CalledProcessError as e:
			print(f"nft error: {e.stderr.decode().strip()}", file=sys.stderr)

	sock.close()
	db.close()
	nft_teardown()
	print("portkeyd: shut down", file=sys.stderr)


if __name__ == "__main__":
	main()
