"""CRSYS hybrid encryption: X25519 encapsulation plus a STREAM-mode AEAD payload.

The overall scheme, for one message::

    CEK <- random(32)                        content key, used exactly once
    for each recipient R:
        eph  <- ephemeral X25519 key pair
        shared    = ECDH(eph_priv, R.x25519)
        KEK,nonce = HKDF-SHA256(shared, info = version|suite|eph_pub|R)
        envelope  = AEAD(KEK, nonce, CEK)
    payload = STREAM-AEAD(CEK) over the plaintext, in chunks
    trailer = Ed25519(sender) over  domain|sender|header|SHA-256(plaintext)  [optional]

The non-obvious but important points:

* The ephemeral key is different for every recipient and every message, so
  encrypting the same file twice under the same key yields unrelated ciphertexts
  (semantic security) and there is no nonce that could ever be reused.
* The header is the AAD of every chunk, so it is not malleable.
* ``cek_commit`` commits to the CEK, preventing a container crafted to decrypt
  into two different plaintexts depending on which key opens it (the "invisible
  salamanders" attack against non-key-committing AEADs).
* The signature also covers the header, which contains the recipient list, so a
  recipient cannot forward the message to a third party and pass it off as a
  signature addressed to them (surreptitious forwarding).
"""

from __future__ import annotations

import hashlib
import io
import os
import secrets
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._util import ChainedStream, Readable, Writable, ct_eq, read_exact
from .armor import MESSAGE_BEGIN, ArmorWriter, armor, dearmor
from .container import (
    ANONYMOUS_FPR,
    DEFAULT_CHUNK_SIZE,
    FLAG_SIGNED,
    MAGIC,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    VERSION,
    Header,
    Recipient,
)
from .errors import (
    CrsysError,
    DecryptionError,
    FormatError,
    NoMatchingRecipient,
    SignatureError,
)
from .keys import KeyPair, PublicKey, format_fingerprint
from .suite import (
    KEY_LEN,
    NONCE_LEN,
    SUITE_CHACHA20POLY1305,
    TAG_LEN,
    aead_for,
    chunk_nonce,
    suite_name,
)

_KEM_INFO = b"CRSY-v1-kem\x00"
_WRAP_AAD = b"CRSY-v1-wrap\x00"
_COMMIT_INFO = b"CRSY-v1-commit\x00"
_SIGN_DOMAIN = b"CRSY-v1-sign\x00"
_DETACHED_DOMAIN = b"CRSY-v1-detached\x00"

TRAILER_LEN = 128  # 64-byte sender public key plus a 64-byte signature
LENGTH_PREFIX = 4

# Armored input has to be buffered to be decoded. Cap it so that pointing the
# tool at a huge non-CRSYS file fails fast instead of exhausting memory.
MAX_ARMOR_BYTES = 64 * 1024 * 1024


@dataclass
class EncryptResult:
    """Outcome of an encryption."""

    recipients: List[str]
    signed_by: Optional[str]
    suite: int
    plaintext_bytes: int
    ciphertext_bytes: int


@dataclass
class DecryptResult:
    """Outcome of a successful decryption."""

    signer: Optional[PublicKey]
    recipient_index: int
    suite: int
    plaintext_bytes: int

    @property
    def signer_fingerprint(self) -> Optional[str]:
        return self.signer.fingerprint_hex if self.signer else None


# ----------------------------------------------------------------- primitives


def _hkdf(ikm: bytes, length: int, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=info).derive(ikm)


def _kem_derive(shared: bytes, suite: int, eph_pub: bytes, recipient: PublicKey):
    """Derive (KEK, nonce), bound to suite, ephemeral key and recipient.

    Including both public keys in ``info`` rules out unknown key share attacks:
    the same ECDH secret cannot be reused in a context with another identity.
    """
    info = _KEM_INFO + bytes([VERSION, suite]) + eph_pub + recipient.to_bytes()
    okm = _hkdf(shared, KEY_LEN + NONCE_LEN, info)
    return okm[:KEY_LEN], okm[KEY_LEN:]


def _commit(cek: bytes) -> bytes:
    return _hkdf(cek, 32, _COMMIT_INFO)


def _encapsulate(cek: bytes, recipient: PublicKey, suite: int,
                 anonymous: bool) -> Recipient:
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()
    shared = eph_priv.exchange(recipient.x25519_object())
    kek, nonce = _kem_derive(shared, suite, eph_pub, recipient)
    wrapped = aead_for(suite, kek).encrypt(nonce, cek, _WRAP_AAD)
    fpr = ANONYMOUS_FPR if anonymous else recipient.fingerprint
    return Recipient(fpr=fpr, eph_pub=eph_pub, wrapped=wrapped)


def _decapsulate(header: Header, keypair: KeyPair):
    """Find the envelope this private key can open.

    Envelopes whose fingerprint matches come first (the normal case, one
    attempt), then all the others, so containers with hidden recipients still
    work at the cost of a few extra ECDH operations.
    """
    my_fpr = keypair.fingerprint
    my_pub = keypair.public_key
    ordered = sorted(
        range(len(header.recipients)),
        key=lambda i: 0 if ct_eq(header.recipients[i].fpr, my_fpr) else 1,
    )
    for index in ordered:
        stanza = header.recipients[index]
        try:
            shared = keypair.exchange(stanza.eph_pub)
        # Broad and silent on purpose: a stanza this key cannot open is the
        # normal case in a multi-recipient container, not an error. Nothing is
        # lost by moving on -- if every stanza fails, the loop falls through to
        # NoMatchingRecipient below, so no failure can be swallowed into a
        # wrong answer.
        except Exception:  # noqa: BLE001, S112
            continue
        kek, nonce = _kem_derive(shared, header.suite, stanza.eph_pub, my_pub)
        try:
            cek = aead_for(header.suite, kek).decrypt(nonce, stanza.wrapped, _WRAP_AAD)
        except InvalidTag:
            continue
        # Belt and braces, and known to be unreachable: WRAPPED_LEN is
        # KEY_LEN + TAG_LEN and Recipient refuses any other length, so 48 bytes
        # of ciphertext always decrypt to exactly 32. Kept because it costs
        # nothing and would catch a future change to those constants; do not
        # spend an afternoon trying to write a test that reaches it. The
        # invariant is pinned in test_defensive.py instead.
        if len(cek) != KEY_LEN:
            continue
        return cek, index
    raise NoMatchingRecipient(
        "no envelope can be opened with key %s: this message is not for you"
        % format_fingerprint(my_fpr)
    )


# -------------------------------------------------------------------- payload


def _write_chunk(
    fout: Writable, aead, counter: int, final: bool, data: bytes, aad: bytes
) -> int:
    ct = aead.encrypt(chunk_nonce(counter, final), data, aad)
    fout.write(len(ct).to_bytes(LENGTH_PREFIX, "big"))
    fout.write(ct)
    return LENGTH_PREFIX + len(ct)


def _read_chunk(stream: Readable, max_ct: int) -> Optional[bytes]:
    """Read one chunk. ``None`` at a clean end of file, exception if truncated."""
    prefix = read_exact(stream, LENGTH_PREFIX)
    if not prefix:
        return None
    if len(prefix) < LENGTH_PREFIX:
        raise FormatError("truncated payload: incomplete length prefix")
    size = int.from_bytes(prefix, "big")
    if size < TAG_LEN or size > max_ct:
        raise FormatError("invalid chunk length: %d" % size)
    ct = read_exact(stream, size)
    if len(ct) != size:
        raise FormatError("truncated payload: incomplete chunk")
    return ct


class _ProgressReader:
    """Count bytes read and report them to a callback.

    Wrapping the input stream rather than adding reporting inside the encryption
    loop keeps progress an external decoration: the cryptographic path is
    identical with or without a progress bar.
    """

    def __init__(self, fobj: Readable, total: int, callback) -> None:
        self._fobj = fobj
        self._total = total
        self._callback = callback
        self._done = 0

    def read(self, n: int = -1) -> bytes:
        data = self._fobj.read(n)
        self._done += len(data)
        self._callback(self._done, self._total)
        return data


def _open_container(fin: Readable) -> Readable:
    """Detect a binary container or an armored block automatically.

    The armored block is searched for anywhere in the text, not just at the
    start, so a whole email can be piped in without trimming it by hand.
    """
    head = read_exact(fin, 4)
    if head == MAGIC:
        return ChainedStream(head, fin)
    if not head:
        raise FormatError("empty input: not a CRSYS container")

    body = read_exact(fin, MAX_ARMOR_BYTES)
    if len(body) == MAX_ARMOR_BYTES and fin.read(1):
        raise FormatError(
            "armored input exceeds %d MiB; binary containers stream without this limit"
            % (MAX_ARMOR_BYTES // (1024 * 1024))
        )
    text = (head + body).decode("utf-8", errors="replace")
    if MESSAGE_BEGIN not in text:
        raise FormatError("unrecognized input: not a CRSYS container")
    return io.BytesIO(dearmor(text))


# ------------------------------------------------------------------ public API


def encrypt_stream(
    fin: Readable,
    fout: Writable,
    recipients: Sequence[PublicKey],
    signer: Optional[KeyPair] = None,
    suite: int = SUITE_CHACHA20POLY1305,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    hide_recipients: bool = False,
) -> EncryptResult:
    """Encrypt ``fin`` into ``fout`` for one or more recipients, optionally signing."""
    recipients = _dedupe(recipients)
    if not recipients:
        raise CrsysError("at least one recipient is required")
    if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
        raise CrsysError(
            "chunk_size must be between %d and %d" % (MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)
        )

    cek = secrets.token_bytes(KEY_LEN)
    header = Header(
        suite=suite,
        flags=FLAG_SIGNED if signer is not None else 0,
        chunk_size=chunk_size,
        cek_commit=_commit(cek),
        recipients=[_encapsulate(cek, r, suite, hide_recipients) for r in recipients],
    )
    hdr = header.to_bytes()
    fout.write(hdr)

    aead = aead_for(suite, cek)
    digest = hashlib.sha256()
    counter = 0
    plaintext_bytes = 0
    written = len(hdr)

    while True:
        data = read_exact(fin, chunk_size)
        if not data:
            break
        digest.update(data)
        plaintext_bytes += len(data)
        written += _write_chunk(fout, aead, counter, False, data, hdr)
        counter += 1
        if len(data) < chunk_size:
            break  # read_exact only returns short at end of input

    trailer = b""
    if signer is not None:
        signer_pub = signer.public_key.to_bytes()
        signature = signer.sign(_SIGN_DOMAIN + signer_pub + hdr + digest.digest())
        trailer = signer_pub + signature
    written += _write_chunk(fout, aead, counter, True, trailer, hdr)

    return EncryptResult(
        recipients=[r.fingerprint_hex for r in recipients],
        signed_by=signer.fingerprint_hex if signer else None,
        suite=suite,
        plaintext_bytes=plaintext_bytes,
        ciphertext_bytes=written,
    )


def decrypt_stream(
    fin: Readable,
    fout: Writable,
    keypair: KeyPair,
    expected_signer: Optional[PublicKey] = None,
) -> DecryptResult:
    """Decrypt ``fin`` into ``fout``.

    Note that because this streams, authenticated chunks are written out as they
    arrive, so the signature is only verified at the very end. When the
    plaintext must not be released before verification, use :func:`decrypt_file`
    or :func:`decrypt_bytes`, which publish the result only once every check has
    passed.
    """
    stream = _open_container(fin)
    header, hdr = Header.read_from(stream)

    cek, index = _decapsulate(header, keypair)
    if not ct_eq(_commit(cek), header.cek_commit):
        raise DecryptionError(
            "content key commitment mismatch: container was tampered with")

    aead = aead_for(header.suite, cek)
    max_ct = header.chunk_size + TAG_LEN
    digest = hashlib.sha256()
    counter = 0
    plaintext_bytes = 0

    pending = _read_chunk(stream, max_ct)
    if pending is None:
        raise FormatError("container has no payload")

    while True:
        nxt = _read_chunk(stream, max_ct)
        final = nxt is None
        try:
            plain = aead.decrypt(chunk_nonce(counter, final), pending, hdr)
        except InvalidTag:
            raise DecryptionError(
                "chunk %d failed authentication: file tampered with, truncated, "
                "or wrong key" % counter
            ) from None
        if final:
            trailer = plain
            break
        # Also unreachable today, for the same kind of reason: max_ct above is
        # chunk_size + TAG_LEN, _read_chunk refuses anything longer, and both
        # AEADs are length-preserving, so plain can never exceed chunk_size. The
        # test asserts which layer actually stops an oversized chunk.
        if len(plain) > header.chunk_size:
            raise FormatError("chunk larger than chunk_size")
        digest.update(plain)
        plaintext_bytes += len(plain)
        fout.write(plain)
        pending = nxt
        counter += 1

    signer = _check_trailer(header, hdr, digest.digest(), trailer, expected_signer)
    return DecryptResult(
        signer=signer,
        recipient_index=index,
        suite=header.suite,
        plaintext_bytes=plaintext_bytes,
    )


def _check_trailer(
    header: Header,
    hdr: bytes,
    plaintext_hash: bytes,
    trailer: bytes,
    expected_signer: Optional[PublicKey],
) -> Optional[PublicKey]:
    if not header.signed:
        if trailer:
            raise FormatError("non-empty final chunk in an unsigned message")
        if expected_signer is not None:
            raise SignatureError(
                "the message is not signed, but a signature from %s was required"
                % expected_signer.fingerprint_hex
            )
        return None

    if len(trailer) != TRAILER_LEN:
        raise SignatureError("malformed signature block")
    signer = PublicKey.from_bytes(trailer[:64])
    signature = trailer[64:]
    # The signer's public key is itself signed. Without that binding, the X25519
    # half could be swapped while the Ed25519 signature stayed valid, letting the
    # message be attributed to an identity with a different fingerprint.
    try:
        signer.ed25519_object().verify(
            signature, _SIGN_DOMAIN + signer.to_bytes() + hdr + plaintext_hash
        )
    except InvalidSignature:
        raise SignatureError(
            "invalid signature: content or sender was altered") from None
    if expected_signer is not None and not ct_eq(
        signer.to_bytes(), expected_signer.to_bytes()
    ):
        raise SignatureError(
            "signed by %s, expected %s"
            % (signer.fingerprint_hex, expected_signer.fingerprint_hex)
        )
    return signer


# ------------------------------------------------------------ bytes convenience


def encrypt_bytes(
    data: bytes,
    recipients: Sequence[PublicKey],
    signer: Optional[KeyPair] = None,
    suite: int = SUITE_CHACHA20POLY1305,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    hide_recipients: bool = False,
    armored: bool = False,
):
    """Encrypt in-memory bytes. Returns ``bytes``, or ``str`` when ``armored``."""
    out = io.BytesIO()
    encrypt_stream(
        io.BytesIO(data), out, recipients, signer, suite, chunk_size, hide_recipients
    )
    blob = out.getvalue()
    return armor(blob) if armored else blob


def decrypt_bytes(
    data, keypair: KeyPair, expected_signer: Optional[PublicKey] = None
) -> bytes:
    """Decrypt bytes (or an armored block) and return the plaintext.

    The result is returned only if every check, signature included, passed.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(data), out, keypair, expected_signer)
    return out.getvalue()


def decrypt_bytes_verbose(
    data, keypair: KeyPair, expected_signer: Optional[PublicKey] = None
):
    """Like :func:`decrypt_bytes` but also returns the ``DecryptResult`` metadata."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    out = io.BytesIO()
    result = decrypt_stream(io.BytesIO(data), out, keypair, expected_signer)
    return out.getvalue(), result


# ------------------------------------------------------------- file convenience


def encrypt_file(
    src: str,
    dst: str,
    recipients: Sequence[PublicKey],
    signer: Optional[KeyPair] = None,
    suite: int = SUITE_CHACHA20POLY1305,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    hide_recipients: bool = False,
    armored: bool = False,
    progress=None,
) -> EncryptResult:
    """Encrypt a file on disk, streaming (memory use is independent of size).

    ``progress`` is called as ``progress(done, total)`` with the plaintext bytes
    read so far; it exists for graphical front-ends.
    """
    tmp = _tmp_path(dst)
    total = os.path.getsize(src)
    try:
        with open(src, "rb") as raw_in, open(tmp, "wb") as raw:
            fin = _ProgressReader(raw_in, total, progress) if progress else raw_in
            if armored:
                with ArmorWriter(raw) as target:
                    result = encrypt_stream(
                        fin, target, recipients, signer, suite, chunk_size,
                        hide_recipients
                    )
            else:
                result = encrypt_stream(
                    fin, raw, recipients, signer, suite, chunk_size, hide_recipients
                )
        os.replace(tmp, dst)
        return result
    except BaseException:
        _unlink(tmp)
        raise


def decrypt_file(
    src: str,
    dst: str,
    keypair: KeyPair,
    expected_signer: Optional[PublicKey] = None,
    progress=None,
) -> DecryptResult:
    """Decrypt a file.

    The plaintext is written to a temporary file and renamed only once
    verification completes, so a tampered container leaves nothing partial at
    the destination.

    ``progress(done, total)`` counts consumed ciphertext bytes.
    """
    tmp = _tmp_path(dst)
    total = os.path.getsize(src)
    try:
        with open(src, "rb") as raw_in, open(tmp, "wb") as fout:
            fin = _ProgressReader(raw_in, total, progress) if progress else raw_in
            result = decrypt_stream(fin, fout, keypair, expected_signer)
        os.replace(tmp, dst)
        return result
    except BaseException:
        _unlink(tmp)
        raise


def inspect_container(fin: Readable) -> dict:
    """Read the public metadata without holding (or needing) any key."""
    stream = _open_container(fin)
    header, _ = Header.read_from(stream)
    return {
        "version": header.version,
        "suite": suite_name(header.suite),
        "suite_id": header.suite,
        "signed": header.signed,
        "chunk_size": header.chunk_size,
        "recipients": [
            "anonymous" if r.is_anonymous else format_fingerprint(r.fpr)
            for r in header.recipients
        ],
        "cek_commit": header.cek_commit.hex(),
    }


# --------------------------------------------------------- detached signatures


def sign_detached(keypair: KeyPair, data: bytes) -> str:
    """Produce an armored detached signature over some bytes."""
    return sign_detached_stream(keypair, io.BytesIO(data))


def sign_detached_stream(keypair: KeyPair, fin: Readable) -> str:
    digest = hashlib.sha256()
    while True:
        block = fin.read(1 << 20)
        if not block:
            break
        digest.update(block)
    signer_pub = keypair.public_key.to_bytes()
    signature = keypair.sign(_DETACHED_DOMAIN + signer_pub + digest.digest())
    from .armor import SIGNATURE_BEGIN, SIGNATURE_END

    return armor(signer_pub + signature, SIGNATURE_BEGIN, SIGNATURE_END)


def verify_detached(
    data: bytes, signature_text: str, expected_signer: Optional[PublicKey] = None
) -> PublicKey:
    return verify_detached_stream(io.BytesIO(data), signature_text, expected_signer)


def verify_detached_stream(
    fin: Readable, signature_text: str, expected_signer: Optional[PublicKey] = None
) -> PublicKey:
    """Verify a detached signature and return the signer's public key."""
    from .armor import SIGNATURE_BEGIN, SIGNATURE_END

    blob = dearmor(signature_text, SIGNATURE_BEGIN, SIGNATURE_END)
    if len(blob) != TRAILER_LEN:
        raise SignatureError("signature block has the wrong length")
    signer = PublicKey.from_bytes(blob[:64])
    signature = blob[64:]

    digest = hashlib.sha256()
    while True:
        block = fin.read(1 << 20)
        if not block:
            break
        digest.update(block)
    try:
        signer.ed25519_object().verify(
            signature, _DETACHED_DOMAIN + signer.to_bytes() + digest.digest()
        )
    except InvalidSignature:
        raise SignatureError("invalid detached signature") from None
    if expected_signer is not None and not ct_eq(
        signer.to_bytes(), expected_signer.to_bytes()
    ):
        raise SignatureError(
            "signed by %s, expected %s"
            % (signer.fingerprint_hex, expected_signer.fingerprint_hex)
        )
    return signer


# ------------------------------------------------------------------- internals


def _dedupe(recipients: Iterable[PublicKey]) -> List[PublicKey]:
    seen = set()
    out: List[PublicKey] = []
    for key in recipients:
        raw = key.to_bytes()
        if raw in seen:
            continue
        seen.add(raw)
        out.append(key)
    return out


def _tmp_path(dst: str) -> str:
    directory = os.path.dirname(os.path.abspath(dst))
    return os.path.join(directory, ".%s.crsys-tmp" % os.path.basename(dst))


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


__all__ = [
    "DecryptResult",
    "EncryptResult",
    "decrypt_bytes",
    "decrypt_bytes_verbose",
    "decrypt_file",
    "decrypt_stream",
    "encrypt_bytes",
    "encrypt_file",
    "encrypt_stream",
    "inspect_container",
    "sign_detached",
    "sign_detached_stream",
    "verify_detached",
    "verify_detached_stream",
]
