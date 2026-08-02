"""Passphrase key derivation: both backends, and every rejection path.

These paths matter more than their line count suggests: the KDF is the only
thing standing between a stolen key file and the private key inside it.
"""

from __future__ import annotations

import unittest

import _ctx  # noqa: F401

from crsys import KeyPair, kdf
from crsys.errors import FormatError, PassphraseError

SALT = b"0123456789abcdef"

CHEAP_SCRYPT = {"n": 1024, "r": 8, "p": 1}
CHEAP_ARGON2 = {"t": 1, "m": 64, "p": 1}

requires_argon2 = unittest.skipUnless(
    kdf.ARGON2_AVAILABLE, "argon2-cffi is not installed")


class TestParamsSerialization(unittest.TestCase):
    def test_header_value_is_sorted_and_stable(self):
        params = kdf.KdfParams("scrypt", {"r": 8, "n": 1024, "p": 1}, SALT)
        self.assertEqual(params.header_value(), "scrypt n=1024,p=1,r=8")

    def test_roundtrip(self):
        for name, values in (("scrypt", CHEAP_SCRYPT), ("argon2id", CHEAP_ARGON2)):
            with self.subTest(name=name):
                original = kdf.KdfParams(name, dict(values), SALT)
                reparsed = kdf.KdfParams.parse(original.header_value(), SALT)
                self.assertEqual(reparsed.name, name)
                self.assertEqual(reparsed.params, values)
                self.assertEqual(reparsed.salt, SALT)

    def test_unknown_algorithm(self):
        for name in ("md5", "pbkdf2", "bcrypt"):
            with self.subTest(name=name), self.assertRaises(FormatError):
                kdf.KdfParams.parse(name, SALT)

    def test_empty_algorithm(self):
        """Regression: an empty `kdf:` header raised IndexError, not FormatError."""
        for value in ("", "   ", "\t", "\n"):
            with self.subTest(value=repr(value)), self.assertRaises(FormatError):
                kdf.KdfParams.parse(value, SALT)

    def test_non_numeric_parameter(self):
        with self.assertRaises(FormatError):
            kdf.KdfParams.parse("scrypt n=abc,r=8,p=1", SALT)

    def test_parameters_may_be_absent(self):
        """Missing parameters fall back to the defaults rather than crashing."""
        params = kdf.KdfParams.parse("scrypt", SALT)
        self.assertEqual(params.params, {})
        self.assertEqual(len(kdf.derive(b"pw", params)), kdf.KEY_LEN)


class TestDeriveScrypt(unittest.TestCase):
    def _params(self, **overrides):
        values = dict(CHEAP_SCRYPT)
        values.update(overrides)
        return kdf.KdfParams("scrypt", values, SALT)

    def test_deterministic(self):
        a = kdf.derive(b"passphrase", self._params())
        b = kdf.derive(b"passphrase", self._params())
        self.assertEqual(a, b)
        self.assertEqual(len(a), kdf.KEY_LEN)

    def test_passphrase_changes_the_key(self):
        a = kdf.derive(b"passphrase", self._params())
        b = kdf.derive(b"passphrasf", self._params())
        self.assertNotEqual(a, b)

    def test_salt_changes_the_key(self):
        a = kdf.derive(b"pw", kdf.KdfParams("scrypt", dict(CHEAP_SCRYPT), SALT))
        b = kdf.derive(b"pw", kdf.KdfParams("scrypt", dict(CHEAP_SCRYPT), SALT[::-1]))
        self.assertNotEqual(a, b)

    def test_cost_changes_the_key(self):
        a = kdf.derive(b"pw", self._params(n=1024))
        b = kdf.derive(b"pw", self._params(n=2048))
        self.assertNotEqual(a, b)

    def test_n_must_be_a_power_of_two(self):
        for n in (1000, 1025, 3072):
            with self.subTest(n=n), self.assertRaises(FormatError):
                kdf.derive(b"pw", self._params(n=n))

    def test_n_bounds(self):
        for n in (0, 512, 1 << 30):
            with self.subTest(n=n), self.assertRaises(FormatError):
                kdf.derive(b"pw", self._params(n=n))

    def test_r_and_p_bounds(self):
        for overrides in ({"r": 0}, {"r": 64}, {"p": 0}, {"p": 32}):
            with self.subTest(**overrides), self.assertRaises(FormatError):
                kdf.derive(b"pw", self._params(**overrides))


@requires_argon2
class TestDeriveArgon2(unittest.TestCase):
    def _params(self, **overrides):
        values = dict(CHEAP_ARGON2)
        values.update(overrides)
        return kdf.KdfParams("argon2id", values, SALT)

    def test_deterministic(self):
        a = kdf.derive(b"passphrase", self._params())
        b = kdf.derive(b"passphrase", self._params())
        self.assertEqual(a, b)
        self.assertEqual(len(a), kdf.KEY_LEN)

    def test_passphrase_changes_the_key(self):
        self.assertNotEqual(kdf.derive(b"pw1", self._params()),
                            kdf.derive(b"pw2", self._params()))

    def test_salt_changes_the_key(self):
        a = kdf.derive(b"pw", kdf.KdfParams("argon2id", dict(CHEAP_ARGON2), SALT))
        b = kdf.derive(b"pw", kdf.KdfParams("argon2id", dict(CHEAP_ARGON2), SALT[::-1]))
        self.assertNotEqual(a, b)

    def test_each_cost_parameter_changes_the_key(self):
        base = kdf.derive(b"pw", self._params())
        for overrides in ({"t": 2}, {"m": 128}, {"p": 2}):
            with self.subTest(**overrides):
                self.assertNotEqual(base, kdf.derive(b"pw", self._params(**overrides)))

    def test_parameter_bounds(self):
        for overrides in ({"t": 0}, {"t": 64}, {"m": 4}, {"m": 4 << 20},
                          {"p": 0}, {"p": 32}):
            with self.subTest(**overrides), self.assertRaises(FormatError):
                kdf.derive(b"pw", self._params(**overrides))

    def test_memory_must_be_at_least_eight_times_parallelism(self):
        """Regression, found by the fuzzer.

        Argon2 requires m >= 8*p. Values inside their own ranges can still
        violate it, and argon2-cffi then raised HashingError -- not a CrsysError,
        so it escaped the error contract.
        """
        for m, p in ((8, 4), (16, 4), (24, 8), (8, 2)):
            with self.subTest(m=m, p=p), self.assertRaises(FormatError) as ctx:
                kdf.derive(b"pw", self._params(m=m, p=p))
            self.assertIn("8*p", str(ctx.exception))

    def test_valid_combination_at_the_boundary_still_works(self):
        self.assertEqual(len(kdf.derive(b"pw", self._params(m=32, p=4))),
                         kdf.KEY_LEN)

    def test_is_the_default_when_available(self):
        self.assertEqual(kdf.default_params().name, "argon2id")

    def test_differs_from_scrypt(self):
        """Same passphrase and salt, different algorithm: keys must not collide."""
        argon = kdf.derive(b"pw", kdf.KdfParams("argon2id", dict(CHEAP_ARGON2), SALT))
        scrypt = kdf.derive(b"pw", kdf.KdfParams("scrypt", dict(CHEAP_SCRYPT), SALT))
        self.assertNotEqual(argon, scrypt)


class TestMemoryCeiling(unittest.TestCase):
    """A hostile key file must not be able to request an enormous allocation.

    Per-parameter ranges are not sufficient on their own: scrypt's cost is
    128*n*r, so values individually inside their bounds can still multiply out
    to terabytes.
    """

    def test_scrypt_combination_within_bounds_but_enormous(self):
        params = kdf.KdfParams("scrypt", {"n": 1 << 22, "r": 32, "p": 1}, SALT)
        self.assertLessEqual(params.params["n"], 1 << 22)  # each bound is satisfied
        self.assertLessEqual(params.params["r"], 32)
        with self.assertRaises(FormatError) as ctx:
            kdf.derive(b"pw", params)
        self.assertIn("refusing", str(ctx.exception))

    @requires_argon2
    def test_argon2_memory_ceiling(self):
        params = kdf.KdfParams("argon2id", {"t": 1, "m": 2 << 20, "p": 1}, SALT)
        with self.assertRaises(FormatError) as ctx:
            kdf.derive(b"pw", params)
        self.assertIn("refusing", str(ctx.exception))

    def test_defaults_are_comfortably_below_the_ceiling(self):
        for params in (kdf.KdfParams("scrypt", dict(kdf.SCRYPT_DEFAULTS), SALT),
                       kdf.KdfParams("argon2id", dict(kdf.ARGON2_DEFAULTS), SALT)):
            with self.subTest(name=params.name):
                if params.name == "argon2id":
                    needed = params.params["m"] * 1024
                else:
                    needed = 128 * params.params["n"] * params.params["r"]
                self.assertLess(needed, kdf.MAX_MEMORY_BYTES)
                self.assertEqual(needed, 128 << 20, "defaults should be 128 MiB")


class TestCommonRejections(unittest.TestCase):
    def test_salt_too_short(self):
        for salt in (b"", b"short"):
            with self.subTest(salt=salt), self.assertRaises(FormatError):
                kdf.derive(b"pw", kdf.KdfParams("scrypt", dict(CHEAP_SCRYPT), salt))

    def test_unsupported_algorithm_at_derive_time(self):
        params = kdf.KdfParams("blake3", {}, SALT)
        with self.assertRaises(FormatError):
            kdf.derive(b"pw", params)

    def test_argon2_key_without_the_library_explains_itself(self):
        """A key file made elsewhere must fail with an actionable message."""
        original = kdf.ARGON2_AVAILABLE
        kdf.ARGON2_AVAILABLE = False
        try:
            with self.assertRaises(FormatError) as ctx:
                kdf.derive(b"pw", kdf.KdfParams("argon2id", dict(CHEAP_ARGON2), SALT))
            self.assertIn("argon2-cffi", str(ctx.exception))
        finally:
            kdf.ARGON2_AVAILABLE = original

    def test_default_params_use_a_fresh_salt(self):
        salts = {kdf.default_params().salt for _ in range(20)}
        self.assertEqual(len(salts), 20)
        self.assertTrue(all(len(s) == kdf.SALT_LEN for s in salts))


class TestKeyFileInteroperability(unittest.TestCase):
    """A key file must reload under whichever KDF it declares."""

    def _write_with(self, params_factory):
        original = kdf.default_params
        kdf.default_params = params_factory
        try:
            key = KeyPair.generate(comment="interop")
            return key, key.to_text(b"pw")
        finally:
            kdf.default_params = original

    def test_scrypt_key_file(self):
        key, text = self._write_with(
            lambda: kdf.KdfParams("scrypt", dict(CHEAP_SCRYPT), SALT))
        self.assertIn("kdf: scrypt", text)
        self.assertEqual(KeyPair.from_text(text, b"pw").secret_bytes(),
                         key.secret_bytes())
        with self.assertRaises(PassphraseError):
            KeyPair.from_text(text, b"wrong")

    @requires_argon2
    def test_argon2_key_file(self):
        key, text = self._write_with(
            lambda: kdf.KdfParams("argon2id", dict(CHEAP_ARGON2), SALT))
        self.assertIn("kdf: argon2id", text)
        self.assertEqual(KeyPair.from_text(text, b"pw").secret_bytes(),
                         key.secret_bytes())
        with self.assertRaises(PassphraseError):
            KeyPair.from_text(text, b"wrong")

    @requires_argon2
    def test_argon2_cost_downgrade_is_detected(self):
        """The parameters are AAD, so weakening them must break the tag."""
        _, text = self._write_with(
            lambda: kdf.KdfParams("argon2id", {"t": 2, "m": 128, "p": 1}, SALT))
        weakened = "\n".join(
            "kdf: argon2id m=64,p=1,t=1" if ln.startswith("kdf:") else ln
            for ln in text.splitlines())
        with self.assertRaises(PassphraseError):
            KeyPair.from_text(weakened, b"pw")

    @requires_argon2
    def test_algorithm_substitution_is_detected(self):
        """Swapping argon2id for scrypt in the header must not silently work."""
        _, text = self._write_with(
            lambda: kdf.KdfParams("argon2id", dict(CHEAP_ARGON2), SALT))
        swapped = "\n".join(
            "kdf: scrypt n=1024,p=1,r=8" if ln.startswith("kdf:") else ln
            for ln in text.splitlines())
        with self.assertRaises(PassphraseError):
            KeyPair.from_text(swapped, b"pw")


if __name__ == "__main__":
    unittest.main()
