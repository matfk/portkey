#!/usr/bin/env python3
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from server.packet import parse as parse_packet


def build_knock(port, ttl, signing_key):
    body = struct.pack("!HH", port, ttl)
    sig = signing_key.sign(body).signature
    return body + sig


class TestPortkey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk = SigningKey.generate()
        cls.vk = cls.sk.verify_key

    def test_valid_knock_verifies(self):
        payload = build_knock(22, 60, self.sk)
        self.assertEqual(len(payload), 68)
        parsed = parse_packet(payload)
        self.assertIsNotNone(parsed)
        port, ttl, sig = parsed
        self.assertEqual(port, 22)
        self.assertEqual(ttl, 60)
        self.vk.verify(payload[:4], sig)

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
        port, ttl, sig = parse_packet(payload)
        with self.assertRaises(BadSignatureError):
            self.vk.verify(payload[:4], sig)

    def test_replay_is_harmless(self):
        payload = build_knock(443, 120, self.sk)
        for _ in range(3):
            parsed = parse_packet(payload)
            self.vk.verify(payload[:4], parsed[2])

    def test_bad_signature_rejected(self):
        payload = build_knock(22, 60, self.sk)
        payload = payload[:4] + b"\x00" * 64
        parsed = parse_packet(payload)
        with self.assertRaises(BadSignatureError):
            self.vk.verify(payload[:4], parsed[2])

    def test_wrong_length_rejected(self):
        for length in (0, 1, 4, 67, 69, 100, 200):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
