"""Selectable AEAD suites and STREAM-mode nonce construction."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .errors import UnsupportedVersion

SUITE_CHACHA20POLY1305 = 1
SUITE_AES256GCM = 2

SUITE_NAMES = {
    SUITE_CHACHA20POLY1305: "x25519-hkdf-sha256+chacha20poly1305",
    SUITE_AES256GCM: "x25519-hkdf-sha256+aes256gcm",
}

SUITE_BY_NAME = {
    "chacha20poly1305": SUITE_CHACHA20POLY1305,
    "chacha": SUITE_CHACHA20POLY1305,
    "aes256gcm": SUITE_AES256GCM,
    "aes": SUITE_AES256GCM,
}

TAG_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32


def aead_for(suite: int, key: bytes):
    """Instantiate the AEAD for the requested suite."""
    if len(key) != KEY_LEN:
        raise ValueError("AEAD key must be %d bytes" % KEY_LEN)
    if suite == SUITE_CHACHA20POLY1305:
        return ChaCha20Poly1305(key)
    if suite == SUITE_AES256GCM:
        return AESGCM(key)
    raise UnsupportedVersion("unknown cipher suite: %d" % suite)


def suite_name(suite: int) -> str:
    return SUITE_NAMES.get(suite, "unknown(%d)" % suite)


# The counter tops out at 2**88, so in practice it can never wrap around.
_MAX_COUNTER = (1 << 88) - 1


def chunk_nonce(counter: int, final: bool) -> bytes:
    """STREAM nonce: 11-byte counter followed by a 1-byte "final chunk" flag.

    Keeping the flag inside the nonce means that dropping chunks off the end of
    a file changes which chunk is the last one: the AEAD tag no longer matches
    and truncation is detected instead of silently yielding a shorter message.
    """
    if counter < 0 or counter > _MAX_COUNTER:
        raise ValueError("chunk counter out of range")
    return counter.to_bytes(11, "big") + (b"\x01" if final else b"\x00")
