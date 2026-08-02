"""Integrity: every manipulation of the container must be detected."""

from __future__ import annotations

import secrets
import unittest

from _ctx import flip_bit

from crsys import KeyPair, decrypt_bytes, encrypt_bytes
from crsys.container import FIXED_HEADER_LEN, RECIPIENT_LEN
from crsys.errors import CrsysError

CHUNK = 1024
HEADER_LEN_1R = FIXED_HEADER_LEN + RECIPIENT_LEN  # 118 bytes with one recipient


class TestBitFlip(unittest.TestCase):
    """A single flipped bit, anywhere in the file, must break decryption."""

    @classmethod
    def setUpClass(cls):
        cls.bob = KeyPair.generate()
        cls.data = secrets.token_bytes(2500)
        cls.sealed = encrypt_bytes(cls.data, [cls.bob.public_key], chunk_size=CHUNK)

    def test_every_byte_is_protected(self):
        failures = []
        for offset in range(len(self.sealed)):
            for bit in (0, 3, 7):
                broken = flip_bit(self.sealed, offset, bit)
                try:
                    decrypt_bytes(broken, self.bob)
                except CrsysError:
                    continue
                except Exception as exc:  # exception outside the documented contract
                    failures.append((offset, bit, "raised %r" % exc))
                else:
                    failures.append((offset, bit, "accepted!"))
        self.assertEqual(failures, [], "undetected tampering: %r" % failures[:10])

    def test_significant_regions(self):
        regions = {
            "magic": 0,
            "version": 4,
            "suite": 5,
            "flags": 6,
            "reserved": 7,
            "chunk_size": 8,
            "cek_commit": 12,
            "n_recipients": 45,
            "recipient_fpr": 46,
            "ephemeral_key": 54,
            "wrapped_cek": 86,
            "length_prefix": HEADER_LEN_1R,
            "payload": HEADER_LEN_1R + 10,
        }
        for name, offset in regions.items():
            with self.subTest(region=name), self.assertRaises(CrsysError):
                decrypt_bytes(flip_bit(self.sealed, offset), self.bob)


class TestTruncation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bob = KeyPair.generate()
        cls.sealed = encrypt_bytes(secrets.token_bytes(3000), [cls.bob.public_key],
                                   chunk_size=CHUNK)

    def test_every_truncation_detected(self):
        for cut in range(len(self.sealed)):
            with self.subTest(cut=cut), self.assertRaises(CrsysError):
                decrypt_bytes(self.sealed[:cut], self.bob)

    def test_final_chunk_removed(self):
        """The empty final chunk is the end marker: removing it must break."""
        without_final = self.sealed[:-20]  # 4 length bytes plus a 16-byte tag
        with self.assertRaises(CrsysError):
            decrypt_bytes(without_final, self.bob)

    def test_appended_data(self):
        for tail in (b"\x00", b"garbage", secrets.token_bytes(64)):
            with self.subTest(), self.assertRaises(CrsysError):
                decrypt_bytes(self.sealed + tail, self.bob)


class TestReordering(unittest.TestCase):
    def test_swapped_chunks(self):
        """The counter lives in the nonce: swapping chunks invalidates the tags."""
        bob = KeyPair.generate()
        sealed = encrypt_bytes(secrets.token_bytes(3 * CHUNK), [bob.public_key],
                               chunk_size=CHUNK)
        block = 4 + CHUNK + 16
        head = sealed[:HEADER_LEN_1R]
        c0 = sealed[HEADER_LEN_1R:HEADER_LEN_1R + block]
        c1 = sealed[HEADER_LEN_1R + block:HEADER_LEN_1R + 2 * block]
        tail = sealed[HEADER_LEN_1R + 2 * block:]
        with self.assertRaises(CrsysError):
            decrypt_bytes(head + c1 + c0 + tail, bob)

    def test_duplicated_chunk(self):
        bob = KeyPair.generate()
        sealed = encrypt_bytes(secrets.token_bytes(2 * CHUNK), [bob.public_key],
                               chunk_size=CHUNK)
        block = 4 + CHUNK + 16
        c0 = sealed[HEADER_LEN_1R:HEADER_LEN_1R + block]
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed[:HEADER_LEN_1R] + c0 + sealed[HEADER_LEN_1R:], bob)


class TestCrossContainer(unittest.TestCase):
    def test_envelope_from_another_message(self):
        """Grafting one message's envelope into another must not work."""
        bob = KeyPair.generate()
        a = encrypt_bytes(b"message A", [bob.public_key], chunk_size=CHUNK)
        b = encrypt_bytes(b"message B", [bob.public_key], chunk_size=CHUNK)
        stanza_a = a[FIXED_HEADER_LEN:FIXED_HEADER_LEN + RECIPIENT_LEN]
        hybrid = (
            b[:FIXED_HEADER_LEN] + stanza_a + b[FIXED_HEADER_LEN + RECIPIENT_LEN:]
        )
        with self.assertRaises(CrsysError):
            decrypt_bytes(hybrid, bob)

    def test_payload_from_another_message(self):
        bob = KeyPair.generate()
        a = encrypt_bytes(b"A" * 500, [bob.public_key], chunk_size=CHUNK)
        b = encrypt_bytes(b"B" * 500, [bob.public_key], chunk_size=CHUNK)
        with self.assertRaises(CrsysError):
            decrypt_bytes(a[:HEADER_LEN_1R] + b[HEADER_LEN_1R:], bob)

    def test_inconsistent_cek_commitment(self):
        """A wrong cek_commit is caught before the payload is even touched."""
        bob = KeyPair.generate()
        sealed = bytearray(encrypt_bytes(b"x", [bob.public_key]))
        sealed[12:44] = secrets.token_bytes(32)
        with self.assertRaises(CrsysError):
            decrypt_bytes(bytes(sealed), bob)


class TestHostileHeaders(unittest.TestCase):
    def _with_header(self, **fields):
        bob = KeyPair.generate()
        sealed = bytearray(encrypt_bytes(b"x", [bob.public_key]))
        for offset, value in fields.items():
            sealed[int(offset[1:]):int(offset[1:]) + len(value)] = value
        return bytes(sealed), bob

    def test_zero_recipients(self):
        sealed, bob = self._with_header(o44=(0).to_bytes(2, "big"))
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed, bob)

    def test_too_many_recipients(self):
        sealed, bob = self._with_header(o44=(60000).to_bytes(2, "big"))
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed, bob)

    def test_absurd_chunk_size(self):
        sealed, bob = self._with_header(o8=(0xFFFFFFFF).to_bytes(4, "big"))
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed, bob)

    def test_future_version(self):
        sealed, bob = self._with_header(o4=b"\x02")
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed, bob)

    def test_unknown_suite(self):
        sealed, bob = self._with_header(o5=b"\x7f")
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed, bob)

    def test_unknown_flags(self):
        sealed, bob = self._with_header(o6=b"\x80")
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed, bob)

    def test_huge_length_prefix(self):
        bob = KeyPair.generate()
        sealed = bytearray(encrypt_bytes(b"x" * 100, [bob.public_key]))
        sealed[HEADER_LEN_1R:HEADER_LEN_1R + 4] = (1 << 30).to_bytes(4, "big")
        with self.assertRaises(CrsysError):
            decrypt_bytes(bytes(sealed), bob)

    def test_zero_length_prefix(self):
        bob = KeyPair.generate()
        sealed = bytearray(encrypt_bytes(b"x" * 100, [bob.public_key]))
        sealed[HEADER_LEN_1R:HEADER_LEN_1R + 4] = (0).to_bytes(4, "big")
        with self.assertRaises(CrsysError):
            decrypt_bytes(bytes(sealed), bob)

    def test_missing_payload(self):
        bob = KeyPair.generate()
        sealed = encrypt_bytes(b"x", [bob.public_key])
        with self.assertRaises(CrsysError):
            decrypt_bytes(sealed[:HEADER_LEN_1R], bob)


if __name__ == "__main__":
    unittest.main()
