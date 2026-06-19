# portkey

Open a remote port by sending a signed UDP packet.

## How it works

```
client                         server
+--------------+ UDP knock    +------------------+
| portkey.py   |------------->| portkeyd         |
| (Ed25519)    |  92 bytes    |   raw socket     |
+--------------+              |   verify signature
                              |   nft add element
                              |   port open (ttl)
                              +------------------+
```

The client builds `port || ttl || timestamp || nonce` (28 bytes), signs it with
an Ed25519 private key (64 byte signature), and sends the 92-byte blob in a
single UDP datagram.  The server captures it on a raw `AF_PACKET` socket
(supports both IPv4 and IPv6), verifies the signature and timestamp, checks the
nonce for replays, and adds the source IP + requested port to an nftables set
with a timeout. No response is returned.

## Quick start

```bash
pip install -r requirements.txt

# Generate a keypair
python -c "
from nacl.signing import SigningKey
sk = SigningKey.generate()
open('portkey.pub', 'wb').write(bytes(sk.verify_key))
open('portkey.key', 'wb').write(bytes(sk))
"

# Move the *private* key to the client machine
mkdir -p ~/.config/portkey
mv portkey.key ~/.config/portkey/key
```

Add the public key to `portkey.toml`:

```toml
[[keys]]
name = "my-machine"
path = "portkey.pub"
```

## Server

```bash
sudo python3 -m server.main --config portkey.toml

sudo python3 -m server.main --config portkey.toml --dry-run
```

The server drops privileges to `nobody:nogroup` after opening the raw socket
(keeping only `NET_RAW` + `NET_ADMIN` capabilities).

### Health check

```bash
echo | nc -U /var/run/portkey/health.sock
```

### Logging

Rotating logs land in the directory configured as `server.logs` (default
`logs/`).  Both a console handler (stderr) and a rotating file handler are
active.

## Client

```bash
python3 client/portkey.py <host> 22 --ttl 30

python3 client/portkey.py <host> 22 --ttl 30 --retries 5 --retry-delay 1.0
```

## Docker

```bash
docker compose up -d
```

The container needs host networking and `NET_RAW` + `NET_ADMIN` capabilities;
both are already configured in `docker-compose.yml`.  A Docker healthcheck
pings the Unix health socket every 30 s.

## Configuration (`portkey.toml`)

```toml
[server]
database        = "portkey.db"          # SQLite nonce store
max_clock_skew  = 60                    # seconds of allowed clock drift
max_ttl         = 86400                 # cap client-requested TTL (24 h)
cleanup_interval = 60                   # nonce DB cleanup interval
logs            = "logs"                # rotating log directory
health_socket   = "/var/run/portkey/health.sock"
nft_binary      = "nft"
user            = "nobody"              # drop to this user after init
group           = "nogroup"

[logging]
level           = "INFO"                # DEBUG, INFO, WARNING, ERROR

[[keys]]
name = "alice"
path = "alice.pub"

[[keys]]
name = "bob"
path = "bob.pub"
```

## Client options

```
portkey <host> <port> [--ttl 60] [--key ~/.config/portkey/key]
                      [--retries 3] [--retry-delay 0.5]
```
