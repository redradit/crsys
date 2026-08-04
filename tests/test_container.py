"""Encryption and decryption: correctness, chunk boundaries, multi-recipient."""

from __future__ import annotations

import io
import os
import secrets
import tempfile
import unittest

import _ctx  # noqa: F401  (sets up sys.path)

from crsys import (
    SUITE_AES256GCM,
    SUITE_CHACHA20POLY1305,
    KeyPair,
    decrypt_bytes,
    decrypt_file,
    decrypt_stream,
    encrypt_bytes,
    encrypt_file,
    encrypt_stream,
    inspect_container,
)
from crsys.armor import MESSAGE_BEGIN
from crsys.container import MAX_CHUNK_SIZE, MIN_CHUNK_SIZE
from crsys.errors import CrsysError, FormatError, NoMatchingRecipient

CHUNK = MIN_CHUNK_SIZE  # 1024: keeps the boundary tests small


class TestRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = KeyPair.generate(comment="alice")
        cls.bob = KeyPair.generate(comment="bob")
        cls.carol = KeyPair.generate(comment="carol")

    def _roundtrip(self, data, **kwargs):
        sealed = encrypt_bytes(data, [self.bob.public_key], chunk_size=CHUNK, **kwargs)
        self.assertEqual(decrypt_bytes(sealed, self.bob), data)
        return sealed

    def test_empty(self):
        self._roundtrip(b"")

    def test_single_byte(self):
        self._roundtrip(b"\x00")
        self._roundtrip(b"\xff")

    def test_plain_text(self):
        self._roundtrip("message with accents: perché però".encode("utf-8"))

    def test_chunk_boundaries(self):
        for size in (
            1,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            2 * CHUNK - 1,
            2 * CHUNK,
            2 * CHUNK + 1,
            3 * CHUNK + 7,
        ):
            with self.subTest(size=size):
                self._roundtrip(secrets.token_bytes(size))

    def test_random_binary(self):
        for _ in range(10):
            self._roundtrip(secrets.token_bytes(secrets.randbelow(5000)))

    def test_both_suites(self):
        data = secrets.token_bytes(3000)
        for suite in (SUITE_CHACHA20POLY1305, SUITE_AES256GCM):
            with self.subTest(suite=suite):
                sealed = encrypt_bytes(data, [self.bob.public_key], suite=suite,
                                       chunk_size=CHUNK)
                self.assertEqual(decrypt_bytes(sealed, self.bob), data)

    def test_semantic_security(self):
        """Same plaintext, same key: the ciphertexts must be uncorrelated."""
        data = b"always the same message"
        sealed = {encrypt_bytes(data, [self.bob.public_key]) for _ in range(20)}
        self.assertEqual(len(sealed), 20)

    def test_multi_recipient(self):
        data = b"meeting at six"
        sealed = encrypt_bytes(data, [self.bob.public_key, self.carol.public_key])
        self.assertEqual(decrypt_bytes(sealed, self.bob), data)
        self.assertEqual(decrypt_bytes(sealed, self.carol), data)

    def test_many_recipients(self):
        keys = [KeyPair.generate() for _ in range(25)]
        sealed = encrypt_bytes(b"broadcast", [k.public_key for k in keys])
        for k in keys:
            self.assertEqual(decrypt_bytes(sealed, k), b"broadcast")

    def test_duplicate_recipients_deduplicated(self):
        sealed = encrypt_bytes(b"x", [self.bob.public_key, self.bob.public_key])
        self.assertEqual(len(inspect_container(io.BytesIO(sealed))["recipients"]), 1)

    def test_outsider_cannot_decrypt(self):
        sealed = encrypt_bytes(b"secret", [self.bob.public_key])
        with self.assertRaises(NoMatchingRecipient):
            decrypt_bytes(sealed, self.carol)

    def test_hidden_recipients(self):
        sealed = encrypt_bytes(b"anonymous",
                               [self.bob.public_key, self.carol.public_key],
                               hide_recipients=True)
        info = inspect_container(io.BytesIO(sealed))
        self.assertEqual(info["recipients"], ["anonymous", "anonymous"])
        self.assertEqual(decrypt_bytes(sealed, self.bob), b"anonymous")
        self.assertEqual(decrypt_bytes(sealed, self.carol), b"anonymous")
        with self.assertRaises(NoMatchingRecipient):
            decrypt_bytes(sealed, KeyPair.generate())

    def test_no_recipients(self):
        with self.assertRaises(CrsysError):
            encrypt_bytes(b"x", [])

    def test_chunk_size_out_of_range(self):
        for size in (0, MIN_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 1):
            with self.subTest(size=size), self.assertRaises(CrsysError):
                encrypt_bytes(b"x", [self.bob.public_key], chunk_size=size)


class TestArmor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bob = KeyPair.generate()

    def test_armored_roundtrip(self):
        data = secrets.token_bytes(5000)
        text = encrypt_bytes(data, [self.bob.public_key], armored=True,
                             chunk_size=CHUNK)
        self.assertIsInstance(text, str)
        self.assertTrue(text.startswith(MESSAGE_BEGIN))
        self.assertTrue(all(len(ln) <= 76 for ln in text.splitlines()))
        self.assertEqual(decrypt_bytes(text, self.bob), data)

    def test_surrounding_text_ignored(self):
        text = encrypt_bytes(b"hello", [self.bob.public_key], armored=True)
        noisy = "Hi Bob,\nsee below:\n\n" + text + "\n-- \nemail signature\n"
        self.assertEqual(decrypt_bytes(noisy, self.bob), b"hello")

    def test_truncated_armor(self):
        text = encrypt_bytes(b"hello", [self.bob.public_key], armored=True)
        with self.assertRaises(FormatError):
            decrypt_bytes(text.replace("-----END CRSYS MESSAGE-----", ""), self.bob)

    def test_unrecognized_input(self):
        for junk in (b"", b"not a container", secrets.token_bytes(500)):
            with self.subTest(), self.assertRaises(FormatError):
                decrypt_bytes(junk, self.bob)

    def test_oversized_armor_rejected(self):
        """A huge non-CRSYS file must fail fast, not exhaust memory."""
        from crsys import core

        original = core.MAX_ARMOR_BYTES
        core.MAX_ARMOR_BYTES = 4096
        try:
            with self.assertRaises(FormatError) as ctx:
                decrypt_bytes(b"-" * 20000, self.bob)
            self.assertIn("exceeds", str(ctx.exception))
        finally:
            core.MAX_ARMOR_BYTES = original


class TestFileApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = KeyPair.generate()
        cls.bob = KeyPair.generate()

    def test_large_file_streaming(self):
        data = secrets.token_bytes(3 * 1024 * 1024 + 12345)
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "large.bin")
            enc = os.path.join(tmp, "large.crsys")
            dec = os.path.join(tmp, "large.out")
            with open(src, "wb") as fh:
                fh.write(data)

            res = encrypt_file(src, enc, [self.bob.public_key], signer=self.alice)
            self.assertEqual(res.plaintext_bytes, len(data))
            self.assertEqual(os.path.getsize(enc), res.ciphertext_bytes)

            out = decrypt_file(enc, dec, self.bob, self.alice.public_key)
            self.assertEqual(out.plaintext_bytes, len(data))
            with open(dec, "rb") as fh:
                self.assertEqual(fh.read(), data)

    def test_progress_callback(self):
        data = secrets.token_bytes(200000)
        seen = []
        with tempfile.TemporaryDirectory() as tmp:
            src, enc = os.path.join(tmp, "a"), os.path.join(tmp, "b")
            with open(src, "wb") as fh:
                fh.write(data)
            encrypt_file(src, enc, [self.bob.public_key], chunk_size=CHUNK,
                         progress=lambda done, total: seen.append((done, total)))
        self.assertTrue(seen)
        self.assertEqual(seen[-1][0], len(data))
        self.assertTrue(all(total == len(data) for _, total in seen))

    def test_armored_file(self):
        data = b"content\nfor testing\n" * 500
        with tempfile.TemporaryDirectory() as tmp:
            src, enc, dec = (os.path.join(tmp, n) for n in ("a", "b", "c"))
            with open(src, "wb") as fh:
                fh.write(data)
            encrypt_file(src, enc, [self.bob.public_key], armored=True,
                         chunk_size=CHUNK)
            with open(enc, "r", encoding="ascii") as fh:
                text = fh.read()
            self.assertTrue(text.startswith(MESSAGE_BEGIN))
            self.assertTrue(all(len(ln) <= 76 for ln in text.splitlines()))
            decrypt_file(enc, dec, self.bob)
            with open(dec, "rb") as fh:
                self.assertEqual(fh.read(), data)

    def test_no_partial_output_on_failure(self):
        """When decryption fails, nothing must be left at the destination."""
        data = secrets.token_bytes(10000)
        with tempfile.TemporaryDirectory() as tmp:
            src, enc, dec = (os.path.join(tmp, n) for n in ("a", "b", "c"))
            with open(src, "wb") as fh:
                fh.write(data)
            encrypt_file(src, enc, [self.bob.public_key], chunk_size=CHUNK)
            with open(enc, "r+b") as fh:
                fh.seek(-40, os.SEEK_END)
                fh.write(b"\x00" * 8)
            with self.assertRaises(CrsysError):
                decrypt_file(enc, dec, self.bob)
            self.assertFalse(os.path.exists(dec))
            self.assertEqual(os.listdir(tmp), sorted(["a", "b"]))


class TestStreamApi(unittest.TestCase):
    def test_stream_to_stream(self):
        bob = KeyPair.generate()
        data = secrets.token_bytes(70000)
        enc = io.BytesIO()
        encrypt_stream(io.BytesIO(data), enc, [bob.public_key], chunk_size=CHUNK)
        dec = io.BytesIO()
        res = decrypt_stream(io.BytesIO(enc.getvalue()), dec, bob)
        self.assertEqual(dec.getvalue(), data)
        self.assertEqual(res.plaintext_bytes, len(data))
        self.assertIsNone(res.signer)


class TestInspect(unittest.TestCase):
    def test_public_metadata(self):
        alice, bob = KeyPair.generate(), KeyPair.generate()
        sealed = encrypt_bytes(b"x", [bob.public_key], signer=alice,
                               suite=SUITE_AES256GCM, chunk_size=4096)
        info = inspect_container(io.BytesIO(sealed))
        self.assertEqual(info["version"], 1)
        self.assertTrue(info["signed"])
        self.assertEqual(info["chunk_size"], 4096)
        self.assertIn("aes256gcm", info["suite"])
        self.assertEqual(info["recipients"], [bob.public_key.fingerprint_hex])
        self.assertEqual(len(info["cek_commit"]), 64)


if __name__ == "__main__":
    unittest.main()
