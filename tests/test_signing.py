"""Sender authentication: embedded signatures and detached signatures."""

from __future__ import annotations

import io
import secrets
import unittest

import _ctx  # noqa: F401

from crsys import (
    KeyPair,
    PublicKey,
    decrypt_bytes,
    decrypt_bytes_verbose,
    encrypt_bytes,
    sign_detached,
    verify_detached,
)
from crsys.armor import SIGNATURE_BEGIN, SIGNATURE_END, armor, dearmor
from crsys.container import FIXED_HEADER_LEN, FLAG_SIGNED, RECIPIENT_LEN, Header
from crsys.core import _decapsulate, _encapsulate
from crsys.errors import CrsysError, SignatureError
from crsys.suite import aead_for, chunk_nonce

HEADER_LEN_1R = FIXED_HEADER_LEN + RECIPIENT_LEN


class TestEmbeddedSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = KeyPair.generate(comment="alice")
        cls.bob = KeyPair.generate(comment="bob")
        cls.mallory = KeyPair.generate(comment="mallory")

    def test_signed_roundtrip(self):
        sealed = encrypt_bytes(b"hi Bob", [self.bob.public_key], signer=self.alice)
        plaintext, res = decrypt_bytes_verbose(sealed, self.bob)
        self.assertEqual(plaintext, b"hi Bob")
        self.assertEqual(res.signer, self.alice.public_key)
        self.assertEqual(res.signer_fingerprint, self.alice.public_key.fingerprint_hex)

    def test_expected_signer_matches(self):
        sealed = encrypt_bytes(b"x", [self.bob.public_key], signer=self.alice)
        self.assertEqual(
            decrypt_bytes(sealed, self.bob, expected_signer=self.alice.public_key), b"x"
        )

    def test_expected_signer_differs(self):
        sealed = encrypt_bytes(b"x", [self.bob.public_key], signer=self.mallory)
        with self.assertRaises(SignatureError):
            decrypt_bytes(sealed, self.bob, expected_signer=self.alice.public_key)

    def test_unsigned_message_but_signature_required(self):
        sealed = encrypt_bytes(b"x", [self.bob.public_key])
        with self.assertRaises(SignatureError):
            decrypt_bytes(sealed, self.bob, expected_signer=self.alice.public_key)

    def test_unsigned_reports_no_signer(self):
        sealed = encrypt_bytes(b"x", [self.bob.public_key])
        _, res = decrypt_bytes_verbose(sealed, self.bob)
        self.assertIsNone(res.signer)
        self.assertIsNone(res.signer_fingerprint)

    def test_tampered_signature(self):
        """The signature block is encrypted, so touching it breaks the AEAD first."""
        sealed = bytearray(
            encrypt_bytes(b"x" * 100, [self.bob.public_key], signer=self.alice)
        )
        sealed[-5] ^= 0x01
        with self.assertRaises(CrsysError):
            decrypt_bytes(bytes(sealed), self.bob)

    def test_signature_over_a_long_file(self):
        data = secrets.token_bytes(200000)
        sealed = encrypt_bytes(data, [self.bob.public_key], signer=self.alice,
                               chunk_size=4096)
        plaintext, res = decrypt_bytes_verbose(sealed, self.bob,
                                               expected_signer=self.alice.public_key)
        self.assertEqual(plaintext, data)
        self.assertEqual(res.signer, self.alice.public_key)

    def test_self_as_recipient(self):
        sealed = encrypt_bytes(b"copy for me",
                               [self.bob.public_key, self.alice.public_key],
                               signer=self.alice)
        self.assertEqual(decrypt_bytes(sealed, self.alice), b"copy for me")
        self.assertEqual(decrypt_bytes(sealed, self.bob), b"copy for me")


class TestSurreptitiousForwarding(unittest.TestCase):
    """Bob must not be able to re-address a message Alice signed for him.

    The signature covers the header, which holds the recipient list, and the
    header is the AAD of every chunk. Rewriting the recipient list therefore
    invalidates the entire payload.
    """

    def test_readdressing_fails(self):
        alice, bob, carol = (KeyPair.generate() for _ in range(3))
        sealed = encrypt_bytes(b"salary approved", [bob.public_key], signer=alice)

        # Bob opens the envelope and recovers the content key: he is a
        # legitimate recipient, so this step is his to take.
        header, _ = Header.read_from(io.BytesIO(sealed))
        cek, _ = _decapsulate(header, bob)

        # Then he tries to rebuild the header in Carol's name, keeping the payload.
        header.recipients = [_encapsulate(cek, carol.public_key, header.suite, False)]
        forged = header.to_bytes() + sealed[HEADER_LEN_1R:]

        self.assertTrue(header.flags & FLAG_SIGNED)
        with self.assertRaises(CrsysError):
            decrypt_bytes(forged, carol)

    def test_plain_forwarding_does_not_open(self):
        alice, bob, carol = (KeyPair.generate() for _ in range(3))
        sealed = encrypt_bytes(b"x", [bob.public_key], signer=alice)
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed, carol)

    def test_recipient_cannot_reattribute_the_signature(self):
        """Bob knows the CEK, so he could rewrite the signature block.

        Changing the X25519 half of the signer identity must still invalidate
        the signature; otherwise Bob could attribute Alice's message to any
        fingerprint he likes.
        """
        alice, bob, mallory = (KeyPair.generate() for _ in range(3))
        sealed = encrypt_bytes(b"x" * 50, [bob.public_key], signer=alice,
                               chunk_size=1024)
        header, hdr = Header.read_from(io.BytesIO(sealed))
        cek, _ = _decapsulate(header, bob)
        aead = aead_for(header.suite, cek)

        chunks = _split_chunks(sealed[len(hdr):])
        last = len(chunks) - 1
        trailer = aead.decrypt(chunk_nonce(last, True), chunks[-1], hdr)
        forged_plain = mallory.public_key.x25519 + trailer[32:]
        chunks[-1] = aead.encrypt(chunk_nonce(last, True), forged_plain, hdr)

        forged = hdr + b"".join(
            len(c).to_bytes(4, "big") + c for c in chunks
        )
        with self.assertRaises(SignatureError):
            decrypt_bytes(forged, bob)


def _split_chunks(payload: bytes):
    """Split the payload into its chunks (tests only; the CLI never needs this)."""
    out, i = [], 0
    while i < len(payload):
        size = int.from_bytes(payload[i:i + 4], "big")
        out.append(payload[i + 4:i + 4 + size])
        i += 4 + size
    return out


class TestDetachedSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = KeyPair.generate()
        cls.mallory = KeyPair.generate()

    def test_roundtrip(self):
        data = b"public document"
        signature = sign_detached(self.alice, data)
        self.assertIn("BEGIN CRSYS SIGNATURE", signature)
        self.assertEqual(verify_detached(data, signature), self.alice.public_key)

    def test_modified_data(self):
        signature = sign_detached(self.alice, b"version 1")
        with self.assertRaises(SignatureError):
            verify_detached(b"version 2", signature)

    def test_expected_signer(self):
        data = b"x"
        signature = sign_detached(self.mallory, data)
        with self.assertRaises(SignatureError):
            verify_detached(data, signature, expected_signer=self.alice.public_key)
        self.assertEqual(
            verify_detached(data, signature, expected_signer=self.mallory.public_key),
            self.mallory.public_key,
        )

    def test_corrupted_signature(self):
        data = b"x" * 1000
        signature = sign_detached(self.alice, data)
        lines = signature.splitlines()
        lines[1] = ("A" if lines[1][0] != "A" else "B") + lines[1][1:]
        with self.assertRaises(CrsysError):
            verify_detached(data, "\n".join(lines))

    def test_missing_block(self):
        with self.assertRaises(CrsysError):
            verify_detached(b"x", "no signature here")

    def test_empty_data(self):
        signature = sign_detached(self.alice, b"")
        self.assertEqual(verify_detached(b"", signature), self.alice.public_key)

    def test_identity_substitution_rejected(self):
        """Regression: the signature must cover the *whole* public key.

        Only the Ed25519 half takes part in verification. If the signature did
        not also bind the X25519 half, anyone could swap it and make a genuine
        signature by Alice appear to come from a different fingerprint.
        """
        data = b"wire transfer authorized"
        signature = sign_detached(self.alice, data)

        blob = bytearray(dearmor(signature, SIGNATURE_BEGIN, SIGNATURE_END))
        blob[:32] = self.mallory.public_key.x25519
        forged = armor(bytes(blob), SIGNATURE_BEGIN, SIGNATURE_END)

        self.assertNotEqual(
            PublicKey.from_bytes(bytes(blob[:64])).fingerprint,
            self.alice.public_key.fingerprint,
        )
        with self.assertRaises(SignatureError):
            verify_detached(data, forged)


if __name__ == "__main__":
    unittest.main()
