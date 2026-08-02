"""Frozen wire-format test vectors.

These are the regression barrier around the container format. The vectors were
produced once by ``make_vectors.py`` and committed; nothing here regenerates
them. If a change to a derivation label, a nonce, the AAD or the framing slips
in, these tests fail — and the correct response is to examine the change, not to
regenerate the vectors.

They are also the interoperability contract: an independent implementation that
decrypts every vector below agrees with this one on the format.
"""

from __future__ import annotations

import base64
import json
import os
import unittest

import _ctx  # noqa: F401

from crsys import KeyPair, PublicKey, decrypt_bytes, decrypt_bytes_verbose
from crsys.errors import CrsysError

VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "vectors.json")


def load_document():
    with open(VECTORS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


class TestVectorFile(unittest.TestCase):
    def setUp(self):
        self.doc = load_document()

    def test_shape(self):
        self.assertEqual(self.doc["format"], "CRSYS container")
        self.assertEqual(self.doc["version"], 1)
        self.assertIn("TEST VECTORS ONLY", self.doc["warning"])
        self.assertTrue(self.doc["vectors"])

    def test_identities_are_self_consistent(self):
        """The published secret really does produce the published public key."""
        for name, entry in self.doc["identities"].items():
            with self.subTest(identity=name):
                keypair = KeyPair(bytes.fromhex(entry["secret_hex"]))
                self.assertEqual(keypair.public_key.to_bytes().hex(),
                                 entry["public_hex"])
                self.assertEqual(keypair.fingerprint_hex, entry["fingerprint"])
                self.assertEqual(
                    PublicKey.from_bytes(bytes.fromhex(entry["public_hex"])),
                    keypair.public_key)

    def test_feature_coverage(self):
        """The vector set must keep exercising every format feature."""
        vectors = self.doc["vectors"]
        self.assertTrue(any(v["signer"] for v in vectors), "no signed vector")
        self.assertTrue(any(not v["signer"] for v in vectors), "no unsigned vector")
        self.assertTrue(any(v["armored"] for v in vectors), "no armored vector")
        self.assertTrue(any(len(v["recipients"]) > 1 for v in vectors),
                        "no multi-recipient vector")
        self.assertTrue(any(not v["plaintext_hex"] for v in vectors),
                        "no empty-plaintext vector")
        self.assertEqual({v["suite"] for v in vectors}, {1, 2},
                         "both cipher suites must appear")


class TestVectorDecryption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load_document()
        cls.people = {
            name: KeyPair(bytes.fromhex(entry["secret_hex"]))
            for name, entry in cls.doc["identities"].items()
        }

    def _container(self, vector):
        return base64.b64decode(vector["container_b64"])

    def test_every_vector_decrypts(self):
        for vector in self.doc["vectors"]:
            with self.subTest(vector=vector["name"]):
                expected = bytes.fromhex(vector["plaintext_hex"])
                container = self._container(vector)
                # Every listed recipient must be able to open it.
                for name in vector["recipients"]:
                    plaintext, info = decrypt_bytes_verbose(
                        container, self.people[name])
                    self.assertEqual(plaintext, expected)
                    self.assertEqual(info.suite, vector["suite"])
                    if vector["signer"]:
                        self.assertEqual(
                            info.signer_fingerprint,
                            self.doc["identities"][vector["signer"]]["fingerprint"])
                    else:
                        self.assertIsNone(info.signer)

    def test_expected_signer_is_enforced(self):
        for vector in self.doc["vectors"]:
            if not vector["signer"]:
                continue
            with self.subTest(vector=vector["name"]):
                container = self._container(vector)
                recipient = self.people[vector["recipients"][0]]
                signer = self.people[vector["signer"]].public_key
                self.assertEqual(
                    decrypt_bytes(container, recipient, expected_signer=signer),
                    bytes.fromhex(vector["plaintext_hex"]))

                impostor = next(k for n, k in self.people.items()
                                if n != vector["signer"])
                with self.assertRaises(CrsysError):
                    decrypt_bytes(container, recipient,
                                  expected_signer=impostor.public_key)

    def test_non_recipients_are_rejected(self):
        for vector in self.doc["vectors"]:
            outsiders = [n for n in self.people if n not in vector["recipients"]]
            if not outsiders:
                continue
            with self.subTest(vector=vector["name"]):
                for name in outsiders:
                    with self.assertRaises(CrsysError):
                        decrypt_bytes(self._container(vector), self.people[name])
                # And a key that appears nowhere in the vector file at all.
                with self.assertRaises(CrsysError):
                    decrypt_bytes(self._container(vector), KeyPair.generate())

    def test_vectors_are_still_tamper_evident(self):
        """The frozen containers must reject modification just like fresh ones."""
        for vector in self.doc["vectors"]:
            if vector["armored"]:
                continue  # whitespace outside the payload is legitimately mutable
            with self.subTest(vector=vector["name"]):
                container = bytearray(self._container(vector))
                container[len(container) // 2] ^= 0x01
                with self.assertRaises(CrsysError):
                    decrypt_bytes(bytes(container),
                                  self.people[vector["recipients"][0]])


if __name__ == "__main__":
    unittest.main()
