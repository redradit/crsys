"""ASCII armor: wraps the binary container in base64 for email and chat."""

from __future__ import annotations

from ._util import b64d, b64e, wrap_b64
from .errors import FormatError

MESSAGE_BEGIN = "-----BEGIN CRSYS MESSAGE-----"
MESSAGE_END = "-----END CRSYS MESSAGE-----"
SIGNATURE_BEGIN = "-----BEGIN CRSYS SIGNATURE-----"
SIGNATURE_END = "-----END CRSYS SIGNATURE-----"


def armor(data: bytes, begin: str = MESSAGE_BEGIN, end: str = MESSAGE_END) -> str:
    return "\n".join([begin, wrap_b64(b64e(data), 76), end]) + "\n"


def dearmor(text: str, begin: str = MESSAGE_BEGIN, end: str = MESSAGE_END) -> bytes:
    """Extract the binary body, ignoring anything outside the markers."""
    lines = [ln.strip() for ln in text.splitlines()]
    try:
        start = lines.index(begin)
        stop = lines.index(end, start + 1)
    except ValueError:
        raise FormatError("CRSYS armored block not found or unterminated") from None
    body = "".join(ln for ln in lines[start + 1:stop] if ln)
    if not body:
        raise FormatError("empty armored block")
    return b64d(body, "armored block")


class ArmorWriter:
    """Emit base64 armor as data arrives, without buffering the whole message.

    Data is accumulated in multiples of 57 bytes because 57 input bytes encode
    to exactly 76 base64 characters -- one full line -- so padding only ever
    appears at the very end.
    """

    _GROUP = 57

    def __init__(self, fout, begin: str = MESSAGE_BEGIN,
                 end: str = MESSAGE_END) -> None:
        self._out = fout
        self._end = end
        self._buf = bytearray()
        self._closed = False
        self._out.write((begin + "\n").encode("ascii"))

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("ArmorWriter is already closed")
        self._buf += data
        take = (len(self._buf) // self._GROUP) * self._GROUP
        if take:
            block, self._buf = self._buf[:take], self._buf[take:]
            lines = [
                b64e(bytes(block[i:i + self._GROUP]))
                for i in range(0, take, self._GROUP)
            ]
            self._out.write(("\n".join(lines) + "\n").encode("ascii"))
        return len(data)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._buf:
            self._out.write((b64e(bytes(self._buf)) + "\n").encode("ascii"))
            self._buf = bytearray()
        self._out.write((self._end + "\n").encode("ascii"))

    def __enter__(self) -> "ArmorWriter":
        return self

    def __exit__(self, *exc) -> None:
        if exc[0] is None:
            self.close()
