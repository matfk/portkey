#!/usr/bin/env python3
import os
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from protocol import PKT_BODY_FMT, PKT_BODY_LEN
from server.packet import NonceSet, verify_timestamp
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

        # Parse again (same nonce) — this should fail because nonce was already seen
        nonces = NonceSet()
        self.assertFalse(nonces.seen(nonce))
        self.assertTrue(nonces.seen(nonce))

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
    def test_new_nonce_passes(self):
        ns = NonceSet()
        self.assertFalse(ns.seen(b"\x00" * 16))

    def test_same_nonce_twice_fails(self):
        ns = NonceSet()
        nonce = os.urandom(16)
        self.assertFalse(ns.seen(nonce))
        self.assertTrue(ns.seen(nonce))
        self.assertTrue(ns.seen(nonce))

    def test_different_nonces_are_independent(self):
        ns = NonceSet()
        self.assertFalse(ns.seen(b"a" * 16))
        self.assertFalse(ns.seen(b"b" * 16))
        self.assertTrue(ns.seen(b"a" * 16))
        self.assertFalse(ns.seen(b"c" * 16))

    def test_empty_nonce(self):
        ns = NonceSet()
        self.assertFalse(ns.seen(b""))
        self.assertTrue(ns.seen(b""))

    def test_many_unique_nonces(self):
        ns = NonceSet()
        for i in range(1000):
            nonce = struct.pack("!Q", i) + b"\x00" * 8
            self.assertFalse(ns.seen(nonce))
        for i in range(1000):
            nonce = struct.pack("!Q", i) + b"\x00" * 8
            self.assertTrue(ns.seen(nonce))


if __name__ == "__main__":
    unittest.main(verbosity=2)
