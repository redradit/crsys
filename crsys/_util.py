"""Shared helpers: robust I/O, strict base64, constant-time comparison."""

from __future__ import annotations

import base64
import binascii
import hmac
from typing import Protocol

from .errors import FormatError


class Readable(Protocol):
    """A source this library reads from. One method, and no promise of seeking.

    ``BinaryIO`` was used here first, and it was an overclaim of exactly the kind
    this project has already had to correct in its prose. It promises ``seek``,
    ``tell``, ``fileno``, ``readline``, ``truncate`` and a dozen more, none of
    which the encryption path ever calls — and none of which the wrappers passed
    around inside it (``ChainedStream``, ``_ProgressReader``) implement. So the
    annotation described a contract the callers could not meet and the callees
    did not want, and it hid the one property that actually matters here: this
    code reads forwards, once, and never seeks. That is what lets it work on a
    pipe.

    The argument is positional-only because ``io.BufferedReader.read`` is, so a
    named parameter here would refuse a real file object.
    """

    def read(self, n: int = ..., /) -> bytes: ...


class Writable(Protocol):
    """A sink this library writes to: one method, returning whatever it likes.

    ``io`` objects return the number of bytes written and other sinks return
    ``None``; nothing in this library inspects the result, so requiring ``int``
    would exclude valid sinks for no gain.
    """

    def write(self, data: bytes, /) -> object: ...


def read_exact(fobj: Readable, n: int) -> bytes:
    """Read exactly ``n`` bytes.

    Returns fewer bytes only at end of stream: ``read()`` is allowed to return
    short reads on pipes and sockets, so a single call can never be trusted.
    """
    if n <= 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        chunk = fobj.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def read_or_fail(fobj: Readable, n: int, what: str) -> bytes:
    """Like :func:`read_exact`, but raise :class:`FormatError` on a short stream."""
    data = read_exact(fobj, n)
    if len(data) != n:
        raise FormatError(
            "truncated file: expected %d bytes for %s, got %d" % (n, what, len(data))
        )
    return data


class ChainedStream:
    """Push already-consumed bytes back in front of a stream (peek without seek)."""

    def __init__(self, prefix: bytes, stream: Readable) -> None:
        self._prefix = prefix
        self._stream = stream

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            out = self._prefix + self._stream.read()
            self._prefix = b""
            return out
        if not self._prefix:
            return self._stream.read(n)
        out = self._prefix[:n]
        self._prefix = self._prefix[len(out):]
        if len(out) < n:
            out += self._stream.read(n - len(out))
        return out


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time comparison (does not leak the first differing byte)."""
    return hmac.compare_digest(a, b)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str, what: str = "field") -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise FormatError("invalid base64 in %s: %s" % (what, exc)) from exc


def b64u_e(data: bytes) -> str:
    """URL-safe base64 without padding, used by the one-line compact form."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_d(text: str, what: str = "field") -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text.encode("ascii") + pad.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise FormatError("invalid base64url in %s: %s" % (what, exc)) from exc


def wrap_b64(text: str, width: int = 64) -> str:
    return "\n".join(text[i:i + width] for i in range(0, len(text), width)) or ""
