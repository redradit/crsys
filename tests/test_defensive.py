"""Drive the library's defensive rejections, one by one.

The rest of the suite attacks CRSYS from the outside: it flips every bit of a
container, truncates it at every offset, and mutates parsers for a hundred
thousand iterations. That found eight of the twelve defects in the README, so it
earns its keep — but it only ever exercises the checks that a *malformed file*
can reach.

Roughly thirty `raise` statements in the library had never executed in any test.
An untested `raise` is worth exactly as much as a comment: nobody has seen it
fire, so nobody knows whether its condition is right, whether it raises the type
the error contract promises, or whether it can fire at all. This project has been
bitten by precisely that twice — finding 6 (an empty `kdf:` header raised
`IndexError`) and finding 8 (argon2-cffi's `HashingError` escaping through the
contract) were both defensive gaps rather than protocol mistakes.

So each test here reaches one rejection and asserts the type *and* that the
message says something. Two of them assert the opposite: that a branch cannot
fire, because working out why turned out to be more interesting than covering it.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest

import _ctx  # noqa: F401  (sets up sys.path)

from crsys import KeyPair, PublicKey
from crsys.armor import (
    ArmorWriter,
    MESSAGE_BEGIN,
    MESSAGE_END,
    SIGNATURE_BEGIN,
    SIGNATURE_END,
    armor,
    dearmor,
)
from crsys.container import (
    COMMIT_LEN,
    EPH_LEN,
    FPR_LEN,
    MAX_RECIPIENTS,
    MIN_CHUNK_SIZE,
    VERSION,
    WRAPPED_LEN,
    Header,
    Recipient,
)
from crsys.core import (
    TRAILER_LEN,
    _decapsulate,
    _write_chunk,
    decrypt_bytes,
    encrypt_bytes,
    verify_detached,
)
from crsys.errors import (
    CrsysError,
    FormatError,
    NoMatchingRecipient,
    SignatureError,
    UnsupportedVersion,
)
from crsys.kdf import _parameter_errors
from crsys.keys import (
    COMPACT_PREFIX,
    PRIVATE_BEGIN,
    PRIVATE_END,
    _parse_block,
    format_fingerprint,
)
from crsys.suite import KEY_LEN, SUITE_CHACHA20POLY1305, TAG_LEN, aead_for, chunk_nonce
from crsys._util import ChainedStream, read_exact


def a_recipient(**over) -> Recipient:
    """A structurally valid recipient stanza, with fields overridable."""
    fields = {
        "fpr": bytes(FPR_LEN),
        "eph_pub": bytes(EPH_LEN),
        "wrapped": bytes(WRAPPED_LEN),
    }
    fields.update(over)
    return Recipient(**fields)


def a_header(**over) -> Header:
    fields = {
        "cek_commit": bytes(COMMIT_LEN),
        "recipients": [a_recipient()],
    }
    fields.update(over)
    return Header(**fields)


class TestRecipientStanza(unittest.TestCase):
    """Recipient sizes. Unreachable from the wire — the parser slices exact
    lengths — so these guard the library against itself."""

    def test_short_fingerprint(self):
        with self.assertRaises(FormatError) as cm:
            a_recipient(fpr=b"short")
        self.assertIn("fingerprint", str(cm.exception))

    def test_short_ephemeral_key(self):
        with self.assertRaises(FormatError) as cm:
            a_recipient(eph_pub=b"short")
        self.assertIn("ephemeral", str(cm.exception))

    def test_short_wrapped_key(self):
        with self.assertRaises(FormatError) as cm:
            a_recipient(wrapped=b"short")
        self.assertIn("wrapped", str(cm.exception))


class TestHeaderValidate(unittest.TestCase):
    """Header.validate() is a second gate.

    read_from() rejects a bad version and a bad recipient count before
    validate() ever sees them, and unpacks cek_commit from a fixed-width struct
    so its length is guaranteed. That makes these three branches unreachable
    from a file — but reachable from to_bytes(), which is the path the library
    itself takes when encrypting. They are the checks that would catch this
    codebase making the mistake, rather than an attacker.
    """

    def test_future_version_is_refused(self):
        with self.assertRaises(UnsupportedVersion) as cm:
            a_header(version=VERSION + 1).validate()
        self.assertIn("version", str(cm.exception))

    def test_commitment_of_the_wrong_length(self):
        with self.assertRaises(FormatError) as cm:
            a_header(cek_commit=b"short").validate()
        self.assertIn("commitment", str(cm.exception))

    def test_no_recipients(self):
        with self.assertRaises(FormatError) as cm:
            a_header(recipients=[]).validate()
        self.assertIn("recipient count", str(cm.exception))

    def test_too_many_recipients(self):
        header = a_header(recipients=[a_recipient()] * (MAX_RECIPIENTS + 1))
        with self.assertRaises(FormatError) as cm:
            header.validate()
        self.assertIn("recipient count", str(cm.exception))

    def test_to_bytes_goes_through_validate(self):
        # Otherwise the guard above protects nothing: the library builds headers
        # and serialises them without calling validate() by hand.
        with self.assertRaises(FormatError):
            a_header(recipients=[]).to_bytes()


class ContainerSurgery(unittest.TestCase):
    """Base class: rebuild a real container's payload with the real content key.

    Several rejections live past the AEAD, so reaching them needs chunks that
    authenticate. Recovering the CEK from a container we own is the only way to
    write those.
    """

    @classmethod
    def setUpClass(cls):
        cls.key = KeyPair.generate()

    def parts(self, plaintext=b"hello", chunk_size=MIN_CHUNK_SIZE, signer=None):
        blob = encrypt_bytes(plaintext, [self.key.public_key],
                             chunk_size=chunk_size, signer=signer)
        header, hdr = Header.read_from(io.BytesIO(blob))
        cek, _index = _decapsulate(header, self.key)
        return header, hdr, cek

    def rebuild(self, hdr, cek, header, chunks):
        """hdr bytes, then the given (data, final) chunks, freshly sealed."""
        out = io.BytesIO()
        out.write(hdr)
        aead = aead_for(header.suite, cek)
        for counter, (data, final) in enumerate(chunks):
            _write_chunk(out, aead, counter, final, data, hdr)
        return out.getvalue()


class TestChunkSizeCeiling(ContainerSurgery):
    def test_an_oversized_chunk_is_stopped_by_the_length_prefix(self):
        """And *not* by the check that appears to be there for it.

        core.py has `if len(plain) > header.chunk_size: raise`. It cannot fire.
        `max_ct` is `chunk_size + TAG_LEN`, `_read_chunk` refuses anything longer,
        and both AEADs are length-preserving, so a plaintext over chunk_size
        always produces a ciphertext over max_ct and dies one layer earlier. This
        test pins which layer actually stops it, so the next person does not spend
        an afternoon trying to reach the inner one.
        """
        header, hdr, cek = self.parts(chunk_size=MIN_CHUNK_SIZE)
        oversized = bytes(MIN_CHUNK_SIZE * 2)
        blob = self.rebuild(hdr, cek, header, [(oversized, False), (b"", True)])

        with self.assertRaises(FormatError) as cm:
            decrypt_bytes(blob, self.key)
        self.assertIn("invalid chunk length", str(cm.exception))

    def test_a_chunk_exactly_at_the_ceiling_is_accepted(self):
        header, hdr, cek = self.parts(chunk_size=MIN_CHUNK_SIZE)
        full = bytes(MIN_CHUNK_SIZE)
        blob = self.rebuild(hdr, cek, header, [(full, False), (b"", True)])
        self.assertEqual(decrypt_bytes(blob, self.key), full)


class TestTrailerRejections(ContainerSurgery):
    def test_unsigned_message_with_a_trailer(self):
        header, hdr, cek = self.parts()
        blob = self.rebuild(hdr, cek, header,
                            [(b"hello", False), (b"unexpected", True)])
        with self.assertRaises(FormatError) as cm:
            decrypt_bytes(blob, self.key)
        self.assertIn("non-empty final chunk", str(cm.exception))

    def test_signed_message_with_a_short_trailer(self):
        signer = KeyPair.generate()
        header, hdr, cek = self.parts(signer=signer)
        self.assertTrue(header.signed, "the fixture must actually be signed")
        blob = self.rebuild(hdr, cek, header,
                            [(b"hello", False), (b"too short", True)])
        with self.assertRaises(SignatureError) as cm:
            decrypt_bytes(blob, self.key)
        self.assertIn("malformed signature block", str(cm.exception))


class TestDecapsulationSkips(unittest.TestCase):
    """The loop that tries each envelope in turn."""

    def test_a_degenerate_ephemeral_key_is_skipped_not_fatal(self):
        """Finding 11's check, exercised through the path that uses it.

        An all-zero ephemeral key drives the X25519 output to all-zero, which
        exchange() refuses as RFC 9180 section 7.1.4 requires. That refusal has to
        behave like "this envelope is not mine" rather than killing decryption,
        because an attacker writes the header and could otherwise turn one bad
        stanza into a denial of service for every recipient in the container.
        """
        key = KeyPair.generate()
        header = a_header(recipients=[a_recipient(eph_pub=bytes(EPH_LEN))])
        with self.assertRaises(NoMatchingRecipient):
            _decapsulate(header, key)

    def test_a_wrong_length_content_key_cannot_occur(self):
        """core.py also has `if len(cek) != KEY_LEN: continue`, and that one is
        unreachable too: WRAPPED_LEN is 48, Recipient refuses any other length,
        and 48 bytes of AEAD ciphertext decrypt to exactly 32. Pinned here as an
        invariant so the claim is checked rather than argued.
        """
        self.assertEqual(WRAPPED_LEN, KEY_LEN + TAG_LEN)
        with self.assertRaises(FormatError):
            a_recipient(wrapped=bytes(WRAPPED_LEN + 1))


class TestKeyRejections(unittest.TestCase):
    def test_public_key_halves_must_be_32_bytes(self):
        with self.assertRaises(FormatError) as cm:
            PublicKey(b"short", bytes(32))
        self.assertIn("32 bytes", str(cm.exception))

    def test_compact_form_needs_its_prefix(self):
        with self.assertRaises(FormatError) as cm:
            PublicKey.from_compact("nothing-like-a-key")
        self.assertIn(COMPACT_PREFIX, str(cm.exception))

    def test_a_private_key_file_with_a_forged_fingerprint(self):
        """The one rejection here that an attacker can actually reach: a key file
        whose declared fingerprint disagrees with the key material in it."""
        key = KeyPair.generate()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "id.key")
            key.save(path, None)
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            real = format_fingerprint(key.fingerprint)
            self.assertIn(real, text, "fixture assumption: the file states it")
            # Flip one digit: still a well-formed fingerprint, just not this key's.
            forged = ("1" if real[0] != "1" else "2") + real[1:]
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text.replace(real, forged))
            with self.assertRaises(FormatError) as cm:
                KeyPair.load(path, None)
            self.assertIn("fingerprint", str(cm.exception))

    def test_block_without_a_blank_line(self):
        text = "%s\nversion: 1\n%s\n" % (PRIVATE_BEGIN, PRIVATE_END)
        with self.assertRaises(FormatError) as cm:
            _parse_block(text, PRIVATE_BEGIN, PRIVATE_END, "private key")
        self.assertIn("blank line", str(cm.exception))

    def test_block_with_an_empty_body(self):
        text = "%s\nversion: 1\n\n%s\n" % (PRIVATE_BEGIN, PRIVATE_END)
        with self.assertRaises(FormatError) as cm:
            _parse_block(text, PRIVATE_BEGIN, PRIVATE_END, "private key")
        self.assertIn("empty body", str(cm.exception))

    def test_hash_and_repr(self):
        key = KeyPair.generate()
        self.assertEqual(hash(key.public_key), hash(key.public_key))
        self.assertIn(key.public_key.fingerprint_hex, repr(key.public_key))
        self.assertIn(key.fingerprint_hex, repr(key))


class TestSuiteGuards(unittest.TestCase):
    def test_aead_key_length(self):
        with self.assertRaises(ValueError) as cm:
            aead_for(SUITE_CHACHA20POLY1305, b"short")
        self.assertIn("%d bytes" % KEY_LEN, str(cm.exception))

    def test_unknown_suite(self):
        with self.assertRaises(UnsupportedVersion) as cm:
            aead_for(0xEE, bytes(KEY_LEN))
        self.assertIn("unknown cipher suite", str(cm.exception))

    def test_counter_out_of_range(self):
        for counter in (-1, 1 << 88):
            with self.assertRaises(ValueError) as cm:
                chunk_nonce(counter, False)
            self.assertIn("out of range", str(cm.exception))

    def test_the_counter_ceiling_itself_is_usable(self):
        self.assertEqual(len(chunk_nonce((1 << 88) - 1, True)), 12)


class TestArmorGuards(unittest.TestCase):
    def test_empty_armored_block(self):
        text = "%s\n%s\n" % (MESSAGE_BEGIN, MESSAGE_END)
        with self.assertRaises(FormatError) as cm:
            dearmor(text, MESSAGE_BEGIN, MESSAGE_END)
        self.assertIn("empty armored block", str(cm.exception))

    def test_writing_after_close(self):
        writer = ArmorWriter(io.BytesIO())
        writer.close()
        with self.assertRaises(ValueError) as cm:
            writer.write(b"more")
        self.assertIn("already closed", str(cm.exception))

    def test_closing_twice_is_harmless(self):
        writer = ArmorWriter(io.BytesIO())
        writer.close()
        writer.close()

    def test_detached_signature_of_the_wrong_length(self):
        text = armor(bytes(TRAILER_LEN - 1), SIGNATURE_BEGIN, SIGNATURE_END)
        with self.assertRaises(SignatureError) as cm:
            verify_detached(b"any content", text)
        self.assertIn("wrong length", str(cm.exception))


class TestKdfErrorContract(unittest.TestCase):
    """The wrapper added for finding 8, which had no test of its own.

    Its whole job is that nothing but CrsysError escapes a KDF, whatever the C
    binding decides to raise. That is a claim about *unknown* exception types, so
    it cannot be tested through argon2 — it has to be tested directly.
    """

    def test_an_unexpected_exception_becomes_a_format_error(self):
        with self.assertRaises(FormatError) as cm, _parameter_errors("scrypt"):
            raise OverflowError("the binding disliked something")
        self.assertIn("scrypt rejected these parameters", str(cm.exception))
        self.assertIsInstance(cm.exception, CrsysError)

    def test_a_format_error_passes_through_unchanged(self):
        original = FormatError("already the right type")
        with self.assertRaises(FormatError) as cm, _parameter_errors("argon2id"):
            raise original
        self.assertIs(cm.exception, original)

    def test_nothing_is_raised_when_nothing_goes_wrong(self):
        with _parameter_errors("scrypt"):
            pass


class TestSmallHelpers(unittest.TestCase):
    def test_read_exact_of_nothing(self):
        self.assertEqual(read_exact(io.BytesIO(b"abc"), 0), b"")
        self.assertEqual(read_exact(io.BytesIO(b"abc"), -5), b"")

    def test_chained_stream_read_to_the_end(self):
        stream = ChainedStream(b"head", io.BytesIO(b"tail"))
        self.assertEqual(stream.read(), b"headtail")
        self.assertEqual(stream.read(), b"")

    def test_chained_stream_spanning_the_join(self):
        stream = ChainedStream(b"head", io.BytesIO(b"tail"))
        self.assertEqual(stream.read(6), b"headta")
        self.assertEqual(stream.read(), b"il")


class TestModuleEntryPoint(unittest.TestCase):
    def test_python_dash_m_crsys_runs(self):
        """`python -m crsys` is a documented way in, and nothing executed it."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ, PYTHONPATH=root)
        # No check=: the returncode is the assertion below.
        proc = subprocess.run(  # noqa: PLW1510
            [sys.executable, "-m", "crsys", "--version"],
            capture_output=True, text=True, cwd=root, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("crsys", proc.stdout.lower() + proc.stderr.lower())


if __name__ == "__main__":
    unittest.main()
