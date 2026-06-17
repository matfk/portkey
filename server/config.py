import os
import sys
from pathlib import Path

from nacl.signing import VerifyKey


def load_dotenv(path=".env"):
	env_file = Path(path)
	if not env_file.is_file():
		env_file = Path(__file__).resolve().parent.parent / ".env"
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


def load_pubkey():
	pubkey_hex = os.environ.get("PORTKEY_PUBKEY")
	if not pubkey_hex:
		print("PORTKEY_PUBKEY not set", file=sys.stderr)
		sys.exit(1)

	try:
		return VerifyKey(bytes.fromhex(pubkey_hex))
	except Exception as e:
		print(f"Invalid PORTKEY_PUBKEY: {e}", file=sys.stderr)
		sys.exit(1)
