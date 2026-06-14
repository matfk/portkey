import subprocess


def setup():
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


def teardown():
    subprocess.run(["nft", "delete", "table", "inet", "portkey"], capture_output=True)


def add(address, port, ttl):
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
