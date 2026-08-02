"""Does file encryption actually stream?

The README states that memory use does not depend on file size. That is a claim
about behaviour, not a description of intent, and until now nothing checked it.
A single misplaced ``read()`` or an accumulating buffer would make it false while
every other test kept passing, because correctness and memory use are
independent -- a version that reads the whole file into RAM produces exactly the
right ciphertext.

The test measures peak allocation at two file sizes and asserts it does not grow
with them. Bounding it at one size would only show the bound; comparing two
sizes is what tests independence.
"""

from __future__ import annotations

import os
import tempfile
import tracemalloc
import unittest

import _ctx  # noqa: F401

from crsys import KeyPair, decrypt_file, encrypt_file

SMALL = 4 * 1024 * 1024
LARGE = 24 * 1024 * 1024

# Streaming holds a few chunks at a time, so peak allocation should sit in the
# hundreds of kilobytes. The margin is deliberately loose: the test must fail on
# "buffers the file", not on an extra copy of a chunk.
GROWTH_TOLERANCE = 4 * 1024 * 1024


def _write(path, size):
    """A file of the requested size, written without holding it all in memory."""
    block = os.urandom(1 << 16)
    with open(path, "wb") as fh:
        written = 0
        while written < size:
            take = min(len(block), size - written)
            fh.write(block[:take])
            written += take


def _peak(fn):
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class TestStreamingMemory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bob = KeyPair.generate()
        cls.alice = KeyPair.generate()

    def _encrypt_peaks(self, tmp, armored=False):
        peaks = {}
        for label, size in (("small", SMALL), ("large", LARGE)):
            src = os.path.join(tmp, "%s.bin" % label)
            dst = os.path.join(tmp, "%s.crsys" % label)
            _write(src, size)
            peaks[label] = _peak(
                lambda s=src, d=dst: encrypt_file(
                    s, d, [self.bob.public_key], signer=self.alice,
                    armored=armored))
            self.assertTrue(os.path.exists(dst))
        return peaks

    def test_encryption_memory_does_not_track_file_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            peaks = self._encrypt_peaks(tmp)
        growth = peaks["large"] - peaks["small"]
        self.assertLess(
            growth, GROWTH_TOLERANCE,
            "peak allocation grew by %d bytes when the input grew by %d: "
            "encryption is buffering rather than streaming"
            % (growth, LARGE - SMALL))
        # And the absolute figure should be nowhere near the file size.
        self.assertLess(peaks["large"], LARGE // 4)

    def test_armored_encryption_also_streams(self):
        """ArmorWriter encodes in fixed groups; it must not accumulate either."""
        with tempfile.TemporaryDirectory() as tmp:
            peaks = self._encrypt_peaks(tmp, armored=True)
        growth = peaks["large"] - peaks["small"]
        self.assertLess(
            growth, GROWTH_TOLERANCE,
            "armored output buffers: peak grew by %d bytes" % growth)

    def test_decryption_memory_does_not_track_file_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            peaks = {}
            for label, size in (("small", SMALL), ("large", LARGE)):
                src = os.path.join(tmp, "%s.bin" % label)
                enc = os.path.join(tmp, "%s.crsys" % label)
                dec = os.path.join(tmp, "%s.out" % label)
                _write(src, size)
                encrypt_file(src, enc, [self.bob.public_key], signer=self.alice)
                peaks[label] = _peak(
                    lambda e=enc, d=dec: decrypt_file(
                        e, d, self.bob, self.alice.public_key))
                self.assertEqual(os.path.getsize(dec), size)

        growth = peaks["large"] - peaks["small"]
        self.assertLess(
            growth, GROWTH_TOLERANCE,
            "peak allocation grew by %d bytes: decryption is buffering" % growth)
        self.assertLess(peaks["large"], LARGE // 4)


class TestLargeFileIntegrity(unittest.TestCase):
    """Streaming is only worth anything if the bytes survive it."""

    def test_round_trip_across_many_chunks(self):
        bob = KeyPair.generate()
        alice = KeyPair.generate()
        # A size that is not a multiple of the chunk size, so the last data
        # chunk is short and the trailer follows a partial chunk.
        size = LARGE + 12345
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "big.bin")
            enc = os.path.join(tmp, "big.crsys")
            dec = os.path.join(tmp, "big.out")
            _write(src, size)

            result = encrypt_file(src, enc, [bob.public_key], signer=alice)
            self.assertEqual(result.plaintext_bytes, size)

            out = decrypt_file(enc, dec, bob, alice.public_key)
            self.assertEqual(out.plaintext_bytes, size)
            self.assertEqual(out.signer, alice.public_key)

            # Compare in blocks; loading both files would defeat the point.
            with open(src, "rb") as a, open(dec, "rb") as b:
                while True:
                    x, y = a.read(1 << 20), b.read(1 << 20)
                    self.assertEqual(x, y)
                    if not x:
                        break

    def test_truncating_a_large_file_is_still_detected(self):
        """Chunk counting must hold up over thousands of chunks, not just three."""
        bob = KeyPair.generate()
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "big.bin")
            enc = os.path.join(tmp, "big.crsys")
            _write(src, SMALL)
            encrypt_file(src, enc, [bob.public_key], chunk_size=1024)

            with open(enc, "rb") as fh:
                data = fh.read()
            with open(enc, "wb") as fh:
                fh.write(data[:-40])

            from crsys.errors import CrsysError

            with self.assertRaises(CrsysError):
                decrypt_file(enc, os.path.join(tmp, "out"), bob)


if __name__ == "__main__":
    unittest.main()
