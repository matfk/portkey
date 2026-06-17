import struct

# layout:
#	port	  unsigned short (2 bytes)
#	ttl		  unsigned short (2 bytes)
#	timestamp unsigned long long (8 bytes)
#	nonce	  16 bytes
#	signature 64 bytes (Ed25519)
PKT_BODY_FMT = struct.Struct("!HHQ16s")
PKT_FMT = struct.Struct("!HHQ16s64s")

PKT_EXPECTED_LEN = PKT_FMT.size
PKT_BODY_LEN = PKT_BODY_FMT.size
PKT_SIG_LEN = 64

PKT_PORT_MIN = 1
PKT_PORT_MAX = 65535
