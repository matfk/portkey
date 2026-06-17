import sys
import tomllib
from pathlib import Path
from pydantic import BaseModel

from nacl.signing import VerifyKey

class Server(BaseModel):
	database: Path = Path("/etc/portkey/portkey.db")
	max_clock_skew: int = 60

class Key(BaseModel):
	name: str
	path: Path

class Config(BaseModel):
	server: Server = Server()
	keys: list[Key] = []

	@classmethod
	def load(cls, path: Path):
		if not path.is_file():
			path = Path(__file__).resolve().parent.parent / "portkey.toml"
		try:
			with open(path, "rb") as f:
				toml = tomllib.load(f)
		except FileNotFoundError:
			toml = {}

		return Config.model_validate(toml)

	def verify_keys(self):
		pubkeys = []
		for key in self.keys:
			try:
				pubkeys.append(VerifyKey(key.path.read_bytes()))
			except Exception as e:
				print(f"Invalid key '{key.name}': {e}", file=sys.stderr)
				sys.exit(1)
		return pubkeys
