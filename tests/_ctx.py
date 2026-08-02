"""Shared test context: package import path and a cheap KDF."""

from __future__ import annotations

import os
import secrets
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from crsys import kdf  # noqa: E402

_REAL_DEFAULT_PARAMS = kdf.default_params


def cheap_params() -> "kdf.KdfParams":
    """Minimum allowed KDF cost: tests should not pay 0.6 s per key."""
    return kdf.KdfParams("scrypt", {"n": 1024, "r": 8, "p": 1}, secrets.token_bytes(16))


class CheapKdf:
    """Context manager that temporarily swaps in the cheap defaults."""

    def __enter__(self):
        kdf.default_params = cheap_params
        return self

    def __exit__(self, *exc):
        kdf.default_params = _REAL_DEFAULT_PARAMS


def flip_bit(data: bytes, byte_index: int, bit: int = 0) -> bytes:
    out = bytearray(data)
    out[byte_index] ^= 1 << bit
    return bytes(out)
