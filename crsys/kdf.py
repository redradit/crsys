"""Passphrase-based key derivation used to protect the private key at rest.

Argon2id when ``argon2-cffi`` is installed, scrypt otherwise (always available
through ``cryptography``). The parameters are stored in the key file header and
authenticated as AAD, so nobody can downgrade the derivation cost without
breaking decryption.
"""

from __future__ import annotations

import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ._util import b64d, b64e
from .errors import FormatError

try:  # pragma: no cover - depends on the environment
    from argon2.low_level import Type as _Argon2Type, hash_secret_raw as _argon2_raw

    ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover
    ARGON2_AVAILABLE = False

SALT_LEN = 16
KEY_LEN = 32

# ~128 MiB and ~0.5 s on desktop hardware: makes offline brute force of a
# decent passphrase prohibitively expensive.
SCRYPT_DEFAULTS = {"n": 1 << 17, "r": 8, "p": 1}
ARGON2_DEFAULTS = {"t": 3, "m": 131072, "p": 4}  # m in KiB -> 128 MiB

# Sanity bounds. The per-parameter ranges alone are not enough: scrypt's cost is
# 128*n*r, so n=2**22 with r=32 asks for roughly 17 TB. The memory ceiling below
# is the binding constraint, and it is what stops a hostile key file from turning
# "open this" into an out-of-memory kill.
_SCRYPT_MAX_N = 1 << 22
_ARGON2_MAX_M = 2 << 20  # 2 GiB expressed in KiB

MAX_MEMORY_BYTES = 1 << 30  # 1 GiB; far above any legitimate parameter set


@dataclass(frozen=True)
class KdfParams:
    """Algorithm name, cost parameters and salt."""

    name: str
    params: Dict[str, int]
    salt: bytes

    def header_value(self) -> str:
        body = ",".join("%s=%d" % (k, self.params[k]) for k in sorted(self.params))
        return "%s %s" % (self.name, body)

    @classmethod
    def parse(cls, value: str, salt: bytes) -> "KdfParams":
        parts = value.strip().split(None, 1)
        if not parts:
            raise FormatError("missing KDF name")
        name = parts[0].lower()
        if name not in ("scrypt", "argon2id"):
            raise FormatError("unsupported KDF: %r" % name)
        params: Dict[str, int] = {}
        if len(parts) > 1 and parts[1].strip():
            for item in parts[1].split(","):
                key, _, raw = item.partition("=")
                key = key.strip()
                try:
                    params[key] = int(raw)
                except ValueError as exc:
                    raise FormatError("non-numeric KDF parameter: %r" % item) from exc
        return cls(name=name, params=params, salt=salt)


@contextmanager
def _parameter_errors(name: str):
    """Turn a backend's own exception into the documented error type.

    The explicit range checks above catch the combinations we know about, but the
    parameters come from a file an attacker may have written. Anything the
    backend still objects to is a bad-parameter problem by definition, and
    callers are entitled to see it as :class:`FormatError` rather than as
    whatever type happens to leak out of the C binding.
    """
    try:
        yield
    except FormatError:
        raise
    except Exception as exc:
        raise FormatError("%s rejected these parameters: %s" % (name, exc)) from None


def default_params() -> KdfParams:
    """Recommended parameters for a freshly generated private key."""
    salt = secrets.token_bytes(SALT_LEN)
    if ARGON2_AVAILABLE:
        return KdfParams("argon2id", dict(ARGON2_DEFAULTS), salt)
    return KdfParams("scrypt", dict(SCRYPT_DEFAULTS), salt)


def derive(passphrase: bytes, params: KdfParams) -> bytes:
    """Derive the 32-byte key that wraps the private key material."""
    if len(params.salt) < 8:
        raise FormatError("KDF salt too short")

    if params.name == "scrypt":
        n = params.params.get("n", SCRYPT_DEFAULTS["n"])
        r = params.params.get("r", SCRYPT_DEFAULTS["r"])
        p = params.params.get("p", SCRYPT_DEFAULTS["p"])
        if n < 1024 or n & (n - 1) or n > _SCRYPT_MAX_N:
            raise FormatError("scrypt parameter n out of range: %d" % n)
        if not (1 <= r <= 32) or not (1 <= p <= 16):
            raise FormatError("scrypt parameters r/p out of range")
        needed = 128 * n * r
        if needed > MAX_MEMORY_BYTES:
            raise FormatError(
                "scrypt parameters would need %d MiB, refusing above %d MiB"
                % (needed >> 20, MAX_MEMORY_BYTES >> 20))
        with _parameter_errors("scrypt"):
            return Scrypt(salt=params.salt, length=KEY_LEN,
                          n=n, r=r, p=p).derive(passphrase)

    if params.name == "argon2id":
        if not ARGON2_AVAILABLE:
            raise FormatError(
                "this key uses argon2id but 'argon2-cffi' is not installed "
                "(pip install argon2-cffi)"
            )
        t = params.params.get("t", ARGON2_DEFAULTS["t"])
        m = params.params.get("m", ARGON2_DEFAULTS["m"])
        p = params.params.get("p", ARGON2_DEFAULTS["p"])
        if not (1 <= t <= 32) or not (8 <= m <= _ARGON2_MAX_M) or not (1 <= p <= 16):
            raise FormatError("argon2id parameters out of range")
        # Argon2 additionally requires m >= 8*p. Values that satisfy their own
        # ranges can still violate it, and the library then raises its own
        # exception type from deep inside.
        if m < 8 * p:
            raise FormatError(
                "argon2id memory cost %d is below the required 8*p = %d" % (m, 8 * p))
        needed = m * 1024
        if needed > MAX_MEMORY_BYTES:
            raise FormatError(
                "argon2id parameters would need %d MiB, refusing above %d MiB"
                % (needed >> 20, MAX_MEMORY_BYTES >> 20))
        with _parameter_errors("argon2id"):
            return _argon2_raw(
                secret=passphrase,
                salt=params.salt,
                time_cost=t,
                memory_cost=m,
                parallelism=p,
                hash_len=KEY_LEN,
                type=_Argon2Type.ID,
            )

    raise FormatError("unsupported KDF: %r" % params.name)


def salt_to_text(salt: bytes) -> str:
    return b64e(salt)


def salt_from_text(text: str) -> bytes:
    return b64d(text, "salt")
