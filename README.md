# portkey

Open a remote TCP port by sending a signed UDP packet.

## Quick start

```bash
pip install -r requirements.txt

# Generate a keypair
mkdir -p keys
python -c "
from nacl.signing import SigningKey
sk = SigningKey.generate()
open('keys/alice.pub', 'wb').write(bytes(sk.verify_key))
open('alice.key', 'wb').write(bytes(sk))
"

# Move the private key to the client machine
mkdir -p ~/.config/portkey
mv alice.key ~/.config/portkey/key
```

Add the public key to `portkey.toml`:

```toml
[[keys]]
name = "alice"
path = "/etc/portkey/keys/alice.pub"
```

## Server

```bash
sudo python3 -m server.main --config portkey.toml

sudo python3 -m server.main --config portkey.toml --dry-run
```

The server runs as root inside the container. Capabilities are limited to
`NET_RAW` + `NET_ADMIN` by Docker.

### Health check

```bash
echo | nc -U /var/run/portkey/health.sock
```

### Logging

Rotating logs land in the directory configured as `server.logs` (default
`logs/`). Both a console handler (stderr) and a rotating file handler are
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

The container uses host networking and `NET_RAW` + `NET_ADMIN` capabilities.
Both are in `docker-compose.yml`. A healthcheck pings the Unix socket every 30s.

## Configuration (`portkey.toml`)

```toml
[server]
database        = "/etc/portkey/portkey.db"
max_clock_skew  = 60
max_ttl         = 86400
cleanup_interval = 60
logs            = "/var/log/portkey"
health_socket   = "/var/run/portkey/health.sock"
nft_binary      = "nft"

[logging]
level           = "INFO"

[[keys]]
name = "alice"
path = "/etc/portkey/keys/alice.pub"
```

## Client options

```
portkey <host> <port> [--ttl 60] [--key ~/.config/portkey/key]
                      [--retries 3] [--retry-delay 0.5]
```
