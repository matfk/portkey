#!/usr/bin/env python3
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pathlib import Path

from protocol import PKT_BODY_FMT, PKT_BODY_LEN
from server.config import Config, Server, Key
from server.database import Database
from server.nonce import NonceSet
from server.packet import verify_timestamp
from server.packet import parse as parse_packet


def build_knock(port, ttl, signing_key, timestamp=None, nonce=None):
	if timestamp is None:
		timestamp = int(time.time())
	if nonce is None:
		nonce = os.urandom(16)
	body = PKT_BODY_FMT.pack(port, ttl, timestamp, nonce)
	sig = signing_key.sign(body).signature
	return body + sig


class TestPortkey(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.sk = SigningKey.generate()
		cls.vk = cls.sk.verify_key

	def test_valid_knock_verifies(self):
		payload = build_knock(22, 60, self.sk)
		self.assertEqual(len(payload), 92)
		parsed = parse_packet(payload)
		self.assertIsNotNone(parsed)
		port, ttl, timestamp, nonce, sig = parsed
		self.assertEqual(port, 22)
		self.assertEqual(ttl, 60)
		self.assertIsInstance(timestamp, int)
		self.assertIsInstance(nonce, bytes)
		self.assertEqual(len(nonce), 16)
		self.vk.verify(payload[:PKT_BODY_LEN], sig)

	def test_different_ports(self):
		for port in (1, 80, 443, 65535):
			payload = build_knock(port, 30, self.sk)
			parsed = parse_packet(payload)
			self.assertIsNotNone(parsed)
			self.assertEqual(parsed[0], port)

	def test_different_ttls(self):
		for ttl in (1, 60, 3600, 65535):
			payload = build_knock(8080, ttl, self.sk)
			parsed = parse_packet(payload)
			self.assertIsNotNone(parsed)
			self.assertEqual(parsed[1], ttl)

	def test_wrong_key_fails(self):
		other = SigningKey.generate()
		payload = build_knock(22, 60, other)
		*_rest, sig = parse_packet(payload)
		with self.assertRaises(BadSignatureError):
			self.vk.verify(payload[:PKT_BODY_LEN], sig)

	def test_replay_rejected(self):
		payload = build_knock(443, 120, self.sk)
		parsed = parse_packet(payload)
		*_, nonce, sig = parsed
		self.vk.verify(payload[:PKT_BODY_LEN], sig)

		db_path = f"/tmp/portkey_test_{os.getpid()}_replay.db"
		if os.path.exists(db_path):
			os.remove(db_path)
		db = Database(db_path)
		nonces = NonceSet(db)
		self.assertFalse(nonces.seen(nonce))
		self.assertTrue(nonces.seen(nonce))
		db.close()
		if os.path.exists(db_path):
			os.remove(db_path)

	def test_bad_signature_rejected(self):
		payload = build_knock(22, 60, self.sk)
		payload = payload[:PKT_BODY_LEN] + b"\x00" * 64
		parsed = parse_packet(payload)
		self.assertIsNotNone(parsed)
		*_, sig = parsed
		with self.assertRaises(BadSignatureError):
			self.vk.verify(payload[:PKT_BODY_LEN], sig)

	def test_wrong_length_rejected(self):
		for length in (0, 1, 4, 67, 91, 93, 100, 200):
			self.assertIsNone(parse_packet(b"A" * length))

	def test_port_zero_rejected(self):
		payload = build_knock(0, 60, self.sk)
		self.assertIsNone(parse_packet(payload))

	def test_port_above_65535_rejected(self):
		body = struct.pack("!HH", 0, 60)
		sig = self.sk.sign(body).signature
		payload = body + sig
		self.assertIsNone(parse_packet(payload))

	def test_ttl_zero_rejected(self):
		payload = build_knock(8080, 0, self.sk)
		self.assertIsNone(parse_packet(payload))

	def test_signingkey_verifykey_roundtrip(self):
		msg = b"hello portkey"
		sig = self.sk.sign(msg).signature
		self.vk.verify(msg, sig)

	def test_serialized_key_roundtrip(self):
		raw = bytes(self.sk)
		reloaded = SigningKey(raw)

		msg = struct.pack("!HH", 9999, 42)
		sig = reloaded.sign(msg).signature

		self.vk.verify(msg, sig)

	def test_file_based_keys_match_spec(self):
		pub_bytes = bytes(self.vk)
		priv_bytes = bytes(self.sk)

		vk = VerifyKey(pub_bytes)
		self.assertEqual(bytes(vk), pub_bytes)

		sk = SigningKey(priv_bytes)

		body = struct.pack("!HH", 22, 60)
		sig = sk.sign(body).signature

		vk.verify(body, sig)


class TestTimestamp(unittest.TestCase):
	def test_exact_now_passes(self):
		now = 1000000.0
		self.assertTrue(verify_timestamp(1000000, now, 60))

	def test_within_skew_passes(self):
		now = 1000000.0
		self.assertTrue(verify_timestamp(1000059, now, 60))
		self.assertTrue(verify_timestamp(999941, now, 60))

	def test_at_boundary_passes(self):
		now = 1000000.0
		self.assertTrue(verify_timestamp(1000060, now, 60))
		self.assertTrue(verify_timestamp(999940, now, 60))

	def test_past_fails(self):
		now = 1000000.0
		self.assertFalse(verify_timestamp(999939, now, 60))

	def test_future_fails(self):
		now = 1000000.0
		self.assertFalse(verify_timestamp(1000061, now, 60))

	def test_custom_skew(self):
		now = 1000000.0
		self.assertTrue(verify_timestamp(1000010, now, 10))
		self.assertFalse(verify_timestamp(1000011, now, 10))

	def test_zero_skew(self):
		now = 1000000.0
		self.assertTrue(verify_timestamp(1000000, now, 0))
		self.assertFalse(verify_timestamp(1000001, now, 0))


class TestNonceSet(unittest.TestCase):
	def setUp(self):
		self.db_path = f"/tmp/portkey_test_{os.getpid()}_{id(self)}.db"
		if os.path.exists(self.db_path):
			os.remove(self.db_path)
		self.db = Database(self.db_path)
		self.ns = NonceSet(self.db)

	def tearDown(self):
		self.db.close()
		if os.path.exists(self.db_path):
			os.remove(self.db_path)

	def test_new_nonce_passes(self):
		self.assertFalse(self.ns.seen(b"\x00" * 16))

	def test_same_nonce_twice_fails(self):
		nonce = os.urandom(16)
		self.assertFalse(self.ns.seen(nonce))
		self.assertTrue(self.ns.seen(nonce))
		self.assertTrue(self.ns.seen(nonce))

	def test_different_nonces_are_independent(self):
		self.assertFalse(self.ns.seen(b"a" * 16))
		self.assertFalse(self.ns.seen(b"b" * 16))
		self.assertTrue(self.ns.seen(b"a" * 16))
		self.assertFalse(self.ns.seen(b"c" * 16))

	def test_empty_nonce(self):
		self.assertFalse(self.ns.seen(b""))
		self.assertTrue(self.ns.seen(b""))

	def test_many_unique_nonces(self):
		for i in range(1000):
			nonce = struct.pack("!Q", i) + b"\x00" * 8
			self.assertFalse(self.ns.seen(nonce))
		for i in range(1000):
			nonce = struct.pack("!Q", i) + b"\x00" * 8
			self.assertTrue(self.ns.seen(nonce))


class TestConfig(unittest.TestCase):
	def setUp(self):
		self.tmpdir = tempfile.mkdtemp(prefix="portkey_test_")
		self.sk = SigningKey.generate()
		self.vk = self.sk.verify_key
		self.pub_path = Path(self.tmpdir) / "portkey.pub"
		self.pub_path.write_bytes(bytes(self.vk))

	def tearDown(self):
		shutil.rmtree(self.tmpdir, ignore_errors=True)

	def write_toml(self, body):
		path = Path(self.tmpdir) / "portkey.toml"
		path.write_text(body)
		return path

	def test_defaults_when_empty(self):
		path = self.write_toml("")
		cfg = Config.load(path)
		self.assertEqual(cfg.server.database, Path("/etc/portkey/portkey.db"))
		self.assertEqual(cfg.server.max_clock_skew, 60)
		self.assertEqual(cfg.keys, [])

	def test_loads_server_section(self):
		path = self.write_toml(
			'[server]\n'
			'database = "/custom/portkey.db"\n'
			'max_clock_skew = 120\n'
		)
		cfg = Config.load(path)
		self.assertEqual(cfg.server.database, Path("/custom/portkey.db"))
		self.assertEqual(cfg.server.max_clock_skew, 120)

	def test_loads_keys(self):
		path = self.write_toml(
			'[[keys]]\n'
			f'name = "mathias"\n'
			f'path = "{self.pub_path}"\n'
		)
		cfg = Config.load(path)
		self.assertEqual(len(cfg.keys), 1)
		self.assertIsInstance(cfg.keys[0], Key)
		self.assertEqual(cfg.keys[0].name, "mathias")
		self.assertEqual(cfg.keys[0].path, self.pub_path)

	def test_verify_keys_returns_pubkeys(self):
		path = self.write_toml(
			'[[keys]]\n'
			'name = "mathias"\n'
			f'path = "{self.pub_path}"\n'
		)
		cfg = Config.load(path)
		pubkeys = cfg.verify_keys()
		self.assertEqual(len(pubkeys), 1)
		self.assertEqual(bytes(pubkeys[0]), bytes(self.vk))

	def test_verify_keys_multiple(self):
		other_sk = SigningKey.generate()
		other_pub_path = Path(self.tmpdir) / "other.pub"
		other_pub_path.write_bytes(bytes(other_sk.verify_key))
		path = self.write_toml(
			'[[keys]]\n'
			'name = "mathias"\n'
			f'path = "{self.pub_path}"\n'
			'[[keys]]\n'
			'name = "other"\n'
			f'path = "{other_pub_path}"\n'
		)
		cfg = Config.load(path)
		pubkeys = cfg.verify_keys()
		self.assertEqual(len(pubkeys), 2)

	def test_verify_keys_empty_returns_empty(self):
		path = self.write_toml("")
		cfg = Config.load(path)
		self.assertEqual(cfg.verify_keys(), [])

	def test_verify_keys_skips_bad_key(self):
		bad_path = Path(self.tmpdir) / "bad.pub"
		bad_path.write_bytes(b"not a valid key")
		path = self.write_toml(
			'[[keys]]\n'
			'name = "bad"\n'
			f'path = "{bad_path}"\n'
		)
		cfg = Config.load(path)
		keys = cfg.verify_keys()
		self.assertEqual(keys, [])

	def test_verify_keys_skips_missing_key_file(self):
		missing = Path(self.tmpdir) / "missing.pub"
		path = self.write_toml(
			'[[keys]]\n'
			'name = "missing"\n'
			f'path = "{missing}"\n'
		)
		cfg = Config.load(path)
		keys = cfg.verify_keys()
		self.assertEqual(keys, [])


if __name__ == "__main__":
	unittest.main(verbosity=2)
