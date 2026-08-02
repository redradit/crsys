"""Key generation, serialization and at-rest protection."""

from __future__ import annotations

import os
import tempfile
import unittest

from _ctx import CheapKdf, cheap_params

from crsys import KeyPair, PublicKey, format_fingerprint, parse_fingerprint
from crsys.errors import FormatError, PassphraseError
from crsys.keys import PRIVATE_BEGIN, PUBLIC_BEGIN


class TestFingerprint(unittest.TestCase):
    def test_length_and_format(self):
        key = KeyPair.generate()
        self.assertEqual(len(key.fingerprint), 8)
        self.assertRegex(key.fingerprint_hex, r"^[0-9a-f]{4}(-[0-9a-f]{4}){3}$")

    def test_deterministic(self):
        key = KeyPair.generate()
        self.assertEqual(key.fingerprint, KeyPair(key.secret_bytes()).fingerprint)

    def test_distinct_keys_distinct_fingerprints(self):
        fingerprints = {KeyPair.generate().fingerprint for _ in range(50)}
        self.assertEqual(len(fingerprints), 50)

    def test_parse_roundtrip(self):
        fpr = KeyPair.generate().fingerprint
        self.assertEqual(parse_fingerprint(format_fingerprint(fpr)), fpr)

    def test_parse_invalid(self):
        with self.assertRaises(FormatError):
            parse_fingerprint("not-hexadecimal")
        with self.assertRaises(FormatError):
            parse_fingerprint("aabb")


class TestPublicKeyFormats(unittest.TestCase):
    def setUp(self):
        self.key = KeyPair.generate(comment="alice@example").public_key

    def test_bytes_roundtrip(self):
        self.assertEqual(PublicKey.from_bytes(self.key.to_bytes()), self.key)

    def test_wrong_length(self):
        with self.assertRaises(FormatError):
            PublicKey.from_bytes(b"\x00" * 63)

    def test_text_roundtrip(self):
        reloaded = PublicKey.from_text(self.key.to_text())
        self.assertEqual(reloaded, self.key)
        self.assertEqual(reloaded.comment, "alice@example")

    def test_compact_roundtrip(self):
        compact = self.key.to_compact()
        self.assertTrue(compact.startswith("crsys1"))
        self.assertNotIn("\n", compact)
        self.assertEqual(PublicKey.from_compact(compact), self.key)

    def test_compact_checksum(self):
        compact = self.key.to_compact()
        broken = compact[:-2] + ("AB" if compact[-2:] != "AB" else "CD")
        with self.assertRaises(FormatError):
            PublicKey.from_compact(broken)

    def test_declared_fingerprint_mismatch(self):
        text = self.key.to_text()
        other = KeyPair.generate().public_key.fingerprint_hex
        broken = "\n".join(
            "fingerprint: " + other if ln.startswith("fingerprint:") else ln
            for ln in text.splitlines()
        )
        with self.assertRaises(FormatError):
            PublicKey.from_text(broken)

    def test_parse_dispatch(self):
        self.assertEqual(PublicKey.parse(self.key.to_compact()), self.key)
        self.assertEqual(PublicKey.parse(self.key.to_text()), self.key)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.pub")
            self.key.save(path)
            self.assertEqual(PublicKey.parse(path), self.key)

    def test_malformed_block(self):
        for text in ("", "garbage", PUBLIC_BEGIN + "\nno blank line\n"):
            with self.assertRaises(FormatError):
                PublicKey.from_text(text)

    def test_parse_rejects_junk_as_format_error(self):
        """Regression, found by the fuzzer.

        Unrecognised input falls through to a path lookup. A NUL byte made
        ``open()`` raise ``ValueError`` and an odd name made it raise ``OSError``,
        both escaping the error contract and reaching the CLI as a traceback.
        """
        for junk in ("", "garbage", "with\x00nul", "a" * 500, "con:/\\|?*",
                     "\x00", "crsys1", "-----BEGIN CRSYS PUBLIC KEY-----"):
            with self.subTest(junk=junk[:20]), self.assertRaises(FormatError):
                PublicKey.parse(junk)

    def test_parse_finds_an_embedded_block(self):
        key = KeyPair.generate().public_key
        wrapped = "Hi, here is my key:\n\n" + key.to_text() + "\nregards\n"
        self.assertEqual(PublicKey.parse(wrapped), key)

    def test_small_order_points_rejected(self):
        ed = KeyPair.generate().public_key.ed25519
        with self.assertRaises(FormatError):
            PublicKey(bytes(32), ed)
        with self.assertRaises(FormatError):
            PublicKey(bytes([1] + [0] * 31), ed)


class TestPrivateKeyFile(unittest.TestCase):
    def test_encrypted_roundtrip(self):
        with CheapKdf():
            key = KeyPair.generate(comment="bob")
            text = key.to_text(b"correct-passphrase")
            self.assertIn(PRIVATE_BEGIN, text)
            self.assertNotIn(key.secret_bytes().hex(), text)
            reloaded = KeyPair.from_text(text, b"correct-passphrase")
        self.assertEqual(reloaded.secret_bytes(), key.secret_bytes())
        self.assertEqual(reloaded.comment, "bob")

    def test_wrong_passphrase(self):
        with CheapKdf():
            text = KeyPair.generate().to_text(b"right")
            with self.assertRaises(PassphraseError):
                KeyPair.from_text(text, b"wrong")

    def test_missing_passphrase(self):
        with CheapKdf():
            text = KeyPair.generate().to_text(b"right")
        with self.assertRaises(PassphraseError):
            KeyPair.from_text(text)

    def test_kdf_parameter_downgrade_detected(self):
        """KDF parameters are AAD: weakening them invalidates the tag."""
        with CheapKdf():
            text = KeyPair.generate().to_text(b"pw")
        broken = "\n".join(
            "kdf: scrypt n=1024,p=1,r=1" if ln.startswith("kdf:") else ln
            for ln in text.splitlines()
        )
        with self.assertRaises(PassphraseError):
            KeyPair.from_text(broken, b"pw")

    def test_tampered_body(self):
        with CheapKdf():
            text = KeyPair.generate().to_text(b"pw")
        lines = text.splitlines()
        idx = lines.index("") + 1
        lines[idx] = ("B" if lines[idx][0] != "B" else "C") + lines[idx][1:]
        with self.assertRaises(PassphraseError):
            KeyPair.from_text("\n".join(lines), b"pw")

    def test_without_passphrase(self):
        key = KeyPair.generate()
        reloaded = KeyPair.from_text(key.to_text(None))
        self.assertEqual(reloaded.secret_bytes(), key.secret_bytes())

    def test_save_to_disk(self):
        with CheapKdf(), tempfile.TemporaryDirectory() as tmp:
            priv = os.path.join(tmp, "id.key")
            pub = os.path.join(tmp, "id.pub")
            key = KeyPair.generate()
            key.save(priv, b"pw")
            key.public_key.save(pub)

            self.assertTrue(KeyPair.is_encrypted(priv))
            self.assertEqual(KeyPair.load(priv, b"pw").secret_bytes(), key.secret_bytes())
            self.assertEqual(PublicKey.load(pub), key.public_key)

            key.save(priv, None)
            self.assertFalse(KeyPair.is_encrypted(priv))

    def test_real_kdf_end_to_end(self):
        """One pass with production parameters, to confirm they are usable."""
        key = KeyPair.generate()
        text = key.to_text(b"a real passphrase")
        self.assertEqual(KeyPair.from_text(text, b"a real passphrase").secret_bytes(),
                         key.secret_bytes())

    def test_kdf_parameters_out_of_range(self):
        from crsys import kdf as kdf_mod

        with self.assertRaises(FormatError):
            kdf_mod.derive(b"pw", kdf_mod.KdfParams("scrypt", {"n": 3, "r": 8, "p": 1},
                                                    b"0" * 16))
        with self.assertRaises(FormatError):
            kdf_mod.derive(b"pw", kdf_mod.KdfParams("scrypt", {"n": 1 << 30, "r": 8, "p": 1},
                                                   b"0" * 16))
        with self.assertRaises(FormatError):
            kdf_mod.KdfParams.parse("md5", b"0" * 16)

    def test_secret_wrong_length(self):
        with self.assertRaises(FormatError):
            KeyPair(b"\x00" * 63)

    def test_cheap_params_are_valid(self):
        self.assertEqual(cheap_params().name, "scrypt")


if __name__ == "__main__":
    unittest.main()
