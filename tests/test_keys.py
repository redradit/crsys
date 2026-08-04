"""Key generation, serialization and at-rest protection."""

from __future__ import annotations

import os
import tempfile
import unittest

from _ctx import CheapKdf, cheap_params

from crsys import KeyPair, PublicKey, format_fingerprint, parse_fingerprint
from crsys.errors import FormatError, PassphraseError
from crsys.keys import (
    PRIVATE_BEGIN,
    PUBLIC_BEGIN,
    check_shared_secret,
    restrict_to_owner,
)


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


class TestSharedSecretValidation(unittest.TestCase):
    """RFC 9180 section 7.1.4: an all-zero X25519 output MUST be rejected.

    The peer key reaches this path straight from a container header, without
    passing through PublicKey, so the small-order blocklist does not cover it.
    OpenSSL happens to refuse these points already, which is why the check does
    not fire in practice -- the point is not to depend on that.
    """

    def test_all_zero_output_rejected(self):
        with self.assertRaises(FormatError) as ctx:
            check_shared_secret(bytes(32))
        self.assertIn("degenerate", str(ctx.exception))

    def test_wrong_length_rejected(self):
        for bad in (b"", b"\x01" * 31, b"\x01" * 33):
            with self.subTest(length=len(bad)), self.assertRaises(FormatError):
                check_shared_secret(bad)

    def test_normal_output_passes_through(self):
        shared = bytes(31) + b"\x01"
        self.assertIs(check_shared_secret(shared), shared)

    def test_real_exchange_is_accepted(self):
        alice, bob = KeyPair.generate(), KeyPair.generate()
        shared = alice.exchange(bob.public_key.x25519)
        self.assertEqual(len(shared), 32)
        self.assertEqual(shared, bob.exchange(alice.public_key.x25519))

    def test_low_order_peer_key_is_refused_somewhere(self):
        """Either our check or the backend must stop it -- but something must."""
        from crsys.keys import _SMALL_ORDER_POINTS

        alice = KeyPair.generate()
        for point in sorted(_SMALL_ORDER_POINTS):
            with self.subTest(point=point[:8].hex()):
                try:
                    shared = alice.exchange(point)
                except Exception:
                    continue  # refused, which is the required outcome
                # If it was accepted, it must at least not be degenerate.
                self.assertTrue(any(shared),
                                "accepted a point yielding an all-zero secret")


class TestFilePermissions(unittest.TestCase):
    """Narrowing a key file's permissions must never lock its owner out.

    The first version of this passed the bare account name to icacls. On a
    machine whose hostname matches the account name that resolved to a malformed
    principal, so the ACL granted access to nobody and stripped everyone else --
    icacls reported success and the private key became unreadable to the person
    who had just created it. For a private key that loss is not recoverable.
    """

    def test_a_saved_key_is_still_readable_by_its_owner(self):
        with CheapKdf(), tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "id.key")
            key = KeyPair.generate()
            key.save(path, b"pw")
            # The assertion that would have caught the lockout.
            self.assertEqual(KeyPair.load(path, b"pw").secret_bytes(),
                             key.secret_bytes())
            with open(path, "rb") as fh:
                self.assertTrue(fh.read())

    def test_save_reports_whether_it_could_restrict(self):
        with CheapKdf(), tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "id.key")
            self.assertIs(KeyPair.generate().save(path, b"pw"), True)

    def test_restricting_a_missing_file_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(restrict_to_owner(os.path.join(tmp, "absent.key")))

    def test_restriction_is_idempotent(self):
        """Rewriting a key -- changing its passphrase -- must not lock it out."""
        with CheapKdf(), tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "id.key")
            key = KeyPair.generate()
            for passphrase in (b"one", b"two", b"three"):
                self.assertTrue(key.save(path, passphrase))
                self.assertEqual(KeyPair.load(path, passphrase).secret_bytes(),
                                 key.secret_bytes())

    @unittest.skipIf(os.name == "nt", "POSIX mode bits")
    def test_posix_mode_is_owner_only(self):
        with CheapKdf(), tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "id.key")
            KeyPair.generate().save(path, b"pw")
            self.assertEqual(os.stat(path).st_mode & 0o077, 0,
                             "group or other can read the private key")

    @unittest.skipUnless(os.name == "nt", "Windows ACLs")
    def test_windows_acl_drops_inherited_entries(self):
        import subprocess

        with CheapKdf(), tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "id.key")
            KeyPair.generate().save(path, b"pw")
            # No check=: this reads icacls output to assert on it. A
            # non-zero exit would show up as an empty listing and fail the
            # assertion below, which is the outcome we want either way.
            listing = subprocess.run(["icacls", path], capture_output=True,  # noqa: PLW1510
                                     text=True).stdout
            # "(I)" marks an inherited entry; after /inheritance:r none remain.
            self.assertNotIn("(I)", listing,
                             "inherited permissions survived on a private key")

    def test_public_keys_are_not_restricted(self):
        """A public key is meant to be handed out; locking it down helps nobody."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "id.pub")
            key = KeyPair.generate().public_key
            key.save(path)
            self.assertEqual(PublicKey.load(path), key)


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
            self.assertEqual(KeyPair.load(priv, b"pw").secret_bytes(),
                             key.secret_bytes())
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
            kdf_mod.derive(
                b"pw",
                kdf_mod.KdfParams("scrypt", {"n": 1 << 30, "r": 8, "p": 1},
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
