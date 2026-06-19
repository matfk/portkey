from __future__ import annotations

import logging
import sys
import tomllib
from pathlib import Path

from nacl.signing import VerifyKey
from pydantic import BaseModel, Field

logger = logging.getLogger("portkey.config")

loaded_config: Config | None = None


class Server(BaseModel):
    database: Path = Path("/etc/portkey/portkey.db")
    max_clock_skew: int = Field(default=60, ge=0, le=3600)
    max_ttl: int = Field(default=86400, ge=1, le=604800)
    cleanup_interval: int = Field(default=60, ge=10)
    logs: Path = Path("/var/log/portkey")
    health_socket: Path = Path("/var/run/portkey/health.sock")
    nft_binary: str = "nft"
    user: str | None = Field(default="nobody")
    group: str | None = Field(default="nogroup")


class Key(BaseModel):
    name: str
    path: Path


class Logging(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s %(levelname)s %(name)s %(message)s"
    datefmt: str = "%Y-%m-%dT%H:%M:%S"


class Config(BaseModel):
    server: Server = Server()
    keys: list[Key] = []
    logging: Logging = Logging()

    @classmethod
    def load(cls, path: Path) -> Config:
        if not path.is_file():
            path = Path(__file__).resolve().parent.parent / "portkey.toml"
        try:
            with open(path, "rb") as f:
                toml = tomllib.load(f)
        except FileNotFoundError:
            toml = {}
        return Config.model_validate(toml)

    def verify_keys(self) -> list[VerifyKey]:
        pubkeys: list[VerifyKey] = []
        for key in self.keys:
            try:
                pubkeys.append(VerifyKey(key.path.read_bytes()))
            except Exception as e:
                logger.critical("Invalid key '%s': %s", key.name, e)
                sys.exit(1)
            else:
                logger.info("Loaded key '%s' from %s", key.name, key.path)
        return pubkeys


def get_config() -> Config:
    global loaded_config
    if loaded_config is None:
        raise RuntimeError("Config not initialized. call initialize_config() first")
    return loaded_config


def initialize_config(path: Path) -> Config:
    global loaded_config
    loaded_config = Config.load(path)
    return loaded_config


def validate_only(path: Path) -> bool:
    try:
        config = Config.load(path)
        config.verify_keys()
        print(f"Config OK: {path}")
        print(f"  database: {config.server.database}")
        print(f"  max_clock_skew: {config.server.max_clock_skew}s")
        print(f"  max_ttl: {config.server.max_ttl}s")
        print(f"  keys: {len(config.keys)}")
        for k in config.keys:
            print(f"    - {k.name}: {k.path}")
        return True
    except Exception as e:
        print(f"Config error: {e}", file=sys.stderr)
        return False
