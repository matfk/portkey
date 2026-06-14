# portkey

Open a remote port by sending a signed UDP packet

## How it works

```
client                         server
+--------------+ UDP knock    +------------------+
| portkey.py   |------------->| portkeyd.py      |
| (key)        |  68 bytes    |   raw socket     |
+--------------+              |   verify Ed25519 |
                              |   nft add element|
                              |   port open      |
                              +------------------+
```

The client signs `port || ttl` (4 bytes) with an Ed25519 private key and sends the 68-byte blob in a single UDP datagram. The server captures it on a raw socket, verifies the signature, and adds the source IP + requested port to an nftables set with ttl. No response it sent back to client.

## Setup

```bash
pip install -r requirements.txt
```

Generate keys:

```bash
python -c "
from nacl.signing import SigningKey
sk = SigningKey.generate()
open('portkey.pub', 'wb').write(bytes(sk.verify_key))
open('portkey.key', 'wb').write(bytes(sk))
"
```

Move the private key where the client expects it:

```bash
mkdir -p ~/.config/portkey
mv portkey.key ~/.config/portkey/key
```

Create `.env` on the server with the public key hex:

```bash
echo "PORTKEY_PUBKEY=$(xxd -p portkey.pub | tr -d '\n')" > .env
```

## Usage

**Server** (needs `CAP_NET_RAW` + `CAP_NET_ADMIN` or `sudo`):

```bash
sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)
python3 server/main.py
```

Or with the module path:

```bash
python3 -m server.main
```

**Client:**

```bash
python3 client/portkey.py <host> 22 --ttl 30
```

## With Docker

Build and run the server in a container:

```bash
docker compose up -d
```

The container needs host networking and `NET_RAW` + `NET_ADMIN` capabilities to capture raw packets and manage nftables. Both are configured in `docker-compose.yml`.

## Options

```
portkey <host> <port> [--ttl 60] [--key ~/.config/portkey/key]
```
