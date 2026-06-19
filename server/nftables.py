from __future__ import annotations

import ipaddress
import logging
import subprocess

logger = logging.getLogger("portkey.nftables")

TABLE_FAMILY = "inet"
TABLE_NAME = "portkey"
SET_V4 = "allowed4"
SET_V6 = "allowed6"
CHAIN_NAME = "input"

RULESET = f"""\
table {TABLE_FAMILY} {TABLE_NAME} {{
    set {SET_V4} {{
        type ipv4_addr . inet_service
        flags dynamic,timeout
        timeout 1s
    }}
    set {SET_V6} {{
        type ipv6_addr . inet_service
        flags dynamic,timeout
        timeout 1s
    }}
    chain {CHAIN_NAME} {{
        type filter hook input priority filter; policy accept;
        ip  saddr . tcp dport @{SET_V4} accept
        ip6 saddr . tcp dport @{SET_V6} accept
    }}
}}
"""


def nft(binary: str, *args: str, check: bool = True, input: bytes | None = None) -> None:
    cmd = [binary, *args]
    logger.debug("Running: %s", " ".join(cmd))
    subprocess.run(cmd, capture_output=True, check=check, input=input)


def table_exists(binary: str) -> bool:
    result = subprocess.run(
        [binary, "list", "table", TABLE_FAMILY, TABLE_NAME],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def setup(binary: str = "nft") -> None:
    if table_exists(binary):
        logger.info("nftables table '%s %s' already exists; reusing",
                     TABLE_FAMILY, TABLE_NAME)
        for set_name in (SET_V4, SET_V6):
            nft(binary, "flush", "set", TABLE_FAMILY, TABLE_NAME, set_name)
    else:
        logger.info("Creating nftables table '%s %s'", TABLE_FAMILY, TABLE_NAME)
        nft(binary, "-f", "/dev/stdin", input=RULESET.encode())


def teardown(binary: str = "nft") -> None:
    logger.info("Removing nftables table '%s %s'", TABLE_FAMILY, TABLE_NAME)
    subprocess.run(
        [binary, "delete", "table", TABLE_FAMILY, TABLE_NAME],
        capture_output=True,
    )


def add(address: str, port: int, ttl: int, binary: str = "nft") -> None:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv4Address):
        set_name = SET_V4
    else:
        set_name = SET_V6

    nft(
        binary,
        "add", "element",
        TABLE_FAMILY, TABLE_NAME, set_name,
        f"{{ {address} . {port} timeout {ttl}s }}",
    )
    logger.info("open %s:%d for %ds", address, port, ttl)
