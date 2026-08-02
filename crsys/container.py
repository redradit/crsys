"""CRSYS container format, version 1.

Binary layout (big-endian). The whole header is used as the AAD of *every*
payload chunk: flipping a single bit in the header -- suite, chunk size,
recipient list -- breaks verification of the first chunk anyone tries to open.

::

    offset  len  field
    0       4    magic          b"CRSY"
    4       1    version        0x01
    5       1    suite          1=ChaCha20-Poly1305  2=AES-256-GCM
    6       1    flags          bit0 = payload is signed
    7       1    reserved       0x00
    8       4    chunk_size     plaintext bytes per chunk
    12      32   cek_commit     commitment to the content encryption key
    44      2    n_recipients   number of envelopes
    46      ...  envelopes      72 bytes each:
                                   8   recipient fingerprint (0 when hidden)
                                   32  ephemeral X25519 public key
                                   48  wrapped CEK (32 + 16-byte tag)

Then the payload: a sequence of ``uint32 length || ciphertext`` chunks.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import BinaryIO, List, Tuple

from ._util import read_exact, read_or_fail
from .errors import FormatError, UnsupportedVersion
from .suite import SUITE_AES256GCM, SUITE_CHACHA20POLY1305

MAGIC = b"CRSY"
VERSION = 1

FLAG_SIGNED = 0x01
_KNOWN_FLAGS = FLAG_SIGNED

FPR_LEN = 8
EPH_LEN = 32
WRAPPED_LEN = 48  # 32 bytes of CEK plus a 16-byte tag
RECIPIENT_LEN = FPR_LEN + EPH_LEN + WRAPPED_LEN
COMMIT_LEN = 32
FIXED_HEADER_LEN = 46

DEFAULT_CHUNK_SIZE = 64 * 1024
MIN_CHUNK_SIZE = 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_RECIPIENTS = 1024

ANONYMOUS_FPR = bytes(FPR_LEN)

_HEADER_STRUCT = struct.Struct(">4sBBBBI32sH")


@dataclass(frozen=True)
class Recipient:
    """One envelope: the content encryption key wrapped for a single recipient."""

    fpr: bytes
    eph_pub: bytes
    wrapped: bytes

    def __post_init__(self) -> None:
        if len(self.fpr) != FPR_LEN:
            raise FormatError("recipient fingerprint has the wrong length")
        if len(self.eph_pub) != EPH_LEN:
            raise FormatError("ephemeral key has the wrong length")
        if len(self.wrapped) != WRAPPED_LEN:
            raise FormatError("wrapped CEK has the wrong length")

    def to_bytes(self) -> bytes:
        return self.fpr + self.eph_pub + self.wrapped

    @property
    def is_anonymous(self) -> bool:
        return self.fpr == ANONYMOUS_FPR


@dataclass
class Header:
    """Container header: cleartext, but fully authenticated."""

    suite: int = SUITE_CHACHA20POLY1305
    flags: int = 0
    chunk_size: int = DEFAULT_CHUNK_SIZE
    cek_commit: bytes = b""
    recipients: List[Recipient] = field(default_factory=list)
    version: int = VERSION

    @property
    def signed(self) -> bool:
        return bool(self.flags & FLAG_SIGNED)

    def to_bytes(self) -> bytes:
        self.validate()
        out = _HEADER_STRUCT.pack(
            MAGIC,
            self.version,
            self.suite,
            self.flags,
            0,
            self.chunk_size,
            self.cek_commit,
            len(self.recipients),
        )
        return out + b"".join(r.to_bytes() for r in self.recipients)

    def validate(self) -> None:
        if self.version != VERSION:
            raise UnsupportedVersion("unsupported container version: %d" % self.version)
        if self.suite not in (SUITE_CHACHA20POLY1305, SUITE_AES256GCM):
            raise UnsupportedVersion("unknown cipher suite: %d" % self.suite)
        if self.flags & ~_KNOWN_FLAGS:
            raise UnsupportedVersion("unknown header flags: 0x%02x" % self.flags)
        if not (MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE):
            raise FormatError("chunk_size out of range: %d" % self.chunk_size)
        if len(self.cek_commit) != COMMIT_LEN:
            raise FormatError("CEK commitment has the wrong length")
        if not (1 <= len(self.recipients) <= MAX_RECIPIENTS):
            raise FormatError("invalid recipient count: %d" % len(self.recipients))

    @classmethod
    def read_from(cls, fobj: BinaryIO) -> Tuple["Header", bytes]:
        """Read the header and also return its raw bytes (needed as AAD)."""
        fixed = read_exact(fobj, FIXED_HEADER_LEN)
        if len(fixed) < FIXED_HEADER_LEN:
            raise FormatError("file too short to be a CRSYS container")
        magic, version, suite, flags, reserved, chunk_size, commit, count = (
            _HEADER_STRUCT.unpack(fixed)
        )
        if magic != MAGIC:
            raise FormatError("unrecognized magic: not a CRSYS file")
        if version != VERSION:
            raise UnsupportedVersion(
                "container is version %d, this build supports %d" % (version, VERSION)
            )
        if reserved != 0:
            raise FormatError("reserved byte is not zero")
        if not (1 <= count <= MAX_RECIPIENTS):
            raise FormatError("invalid recipient count: %d" % count)

        blob = read_or_fail(fobj, count * RECIPIENT_LEN, "recipient list")
        recipients = []
        for i in range(count):
            chunk = blob[i * RECIPIENT_LEN:(i + 1) * RECIPIENT_LEN]
            recipients.append(
                Recipient(
                    fpr=chunk[:FPR_LEN],
                    eph_pub=chunk[FPR_LEN:FPR_LEN + EPH_LEN],
                    wrapped=chunk[FPR_LEN + EPH_LEN:],
                )
            )

        header = cls(
            suite=suite,
            flags=flags,
            chunk_size=chunk_size,
            cek_commit=commit,
            recipients=recipients,
            version=version,
        )
        header.validate()
        return header, fixed + blob
