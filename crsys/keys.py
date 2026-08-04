"""CRSYS keys: an X25519 (encryption) plus Ed25519 (signing) pair.

A CRSYS identity is made of two distinct keys with separate roles:

* **X25519** for key agreement (ECDH) -- used to encrypt;
* **Ed25519** for signatures -- used to authenticate the sender.

Keeping them separate is deliberate: reusing one key for two different
primitives is a classic source of cross-protocol attacks.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import kdf
from ._util import b64d, b64e, b64u_d, b64u_e, ct_eq, wrap_b64
from .errors import FormatError, PassphraseError
from .suite import NONCE_LEN, SUITE_CHACHA20POLY1305, aead_for

FPR_LEN = 8
PUBKEY_LEN = 64
SECRET_LEN = 64
COMPACT_PREFIX = "crsys1"

_FPR_DOMAIN = b"CRSY-fpr-v1\x00"
_KEYFILE_AAD_DOMAIN = b"CRSY-keyfile-v1\x00"
_KEYFILE_VERSION = 1

PUBLIC_BEGIN = "-----BEGIN CRSYS PUBLIC KEY-----"
PUBLIC_END = "-----END CRSYS PUBLIC KEY-----"
PRIVATE_BEGIN = "-----BEGIN CRSYS PRIVATE KEY-----"
PRIVATE_END = "-----END CRSYS PRIVATE KEY-----"

# Header fields cryptographically bound to the encrypted body: changing any of
# them invalidates the AEAD tag, so the KDF parameters cannot be downgraded.
_AAD_FIELDS = ("version", "cipher", "kdf", "salt", "nonce", "fingerprint")


def check_shared_secret(shared: bytes) -> bytes:
    """Reject a degenerate X25519 output (RFC 9180 section 7.1.4).

    An all-zero shared secret means the peer supplied a low-order point, so the
    "secret" is a constant the attacker knows.
    """
    if len(shared) != 32:
        raise FormatError("X25519 output must be 32 bytes")
    if not any(shared):
        raise FormatError("degenerate X25519 shared secret: low-order peer key")
    return shared


def _fingerprint(x_pub: bytes, ed_pub: bytes) -> bytes:
    return hashlib.sha256(_FPR_DOMAIN + x_pub + ed_pub).digest()[:FPR_LEN]


def format_fingerprint(fpr: bytes) -> str:
    """Render a fingerprint so it can be read aloud: ``a1b2-c3d4-e5f6-0718``."""
    text = fpr.hex()
    return "-".join(text[i:i + 4] for i in range(0, len(text), 4))


def parse_fingerprint(text: str) -> bytes:
    raw = text.strip().replace("-", "").replace(" ", "").replace(":", "")
    try:
        fpr = bytes.fromhex(raw)
    except ValueError as exc:
        raise FormatError("invalid fingerprint: %r" % text) from exc
    if len(fpr) != FPR_LEN:
        raise FormatError("fingerprint must be %d bytes" % FPR_LEN)
    return fpr


class PublicKey:
    """A public key: 32 bytes of X25519 followed by 32 bytes of Ed25519."""

    __slots__ = ("_x", "_ed", "comment")

    def __init__(self, x_pub: bytes, ed_pub: bytes, comment: str = "") -> None:
        if len(x_pub) != 32 or len(ed_pub) != 32:
            raise FormatError("public keys must be 32 bytes each")
        # Reject small-order curve points: with those, ECDH degenerates into a
        # constant, predictable shared secret.
        if x_pub in _SMALL_ORDER_POINTS:
            raise FormatError("small-order X25519 public key, rejected")
        # The Ed25519 half needs its own check, for a sharper reason. With the
        # identity point as the public key, the signature (R=identity, S=0)
        # satisfies the verification equation for *every* message: a universal
        # forgery that needs no private key at all. OpenSSL accepts such keys and
        # verifies such signatures, so this has to be caught here. See "Taming
        # the many EdDSAs", Chalkias, Garillot and Nikolaenko.
        if ed_pub in _ED25519_SMALL_ORDER_POINTS:
            raise FormatError("small-order Ed25519 public key, rejected")
        # Validate the encoding up front so errors surface on load rather than
        # halfway through an encryption.
        Ed25519PublicKey.from_public_bytes(ed_pub)
        X25519PublicKey.from_public_bytes(x_pub)
        self._x = x_pub
        self._ed = ed_pub
        self.comment = comment

    @property
    def x25519(self) -> bytes:
        return self._x

    @property
    def ed25519(self) -> bytes:
        return self._ed

    @property
    def fingerprint(self) -> bytes:
        return _fingerprint(self._x, self._ed)

    @property
    def fingerprint_hex(self) -> str:
        return format_fingerprint(self.fingerprint)

    def to_bytes(self) -> bytes:
        return self._x + self._ed

    @classmethod
    def from_bytes(cls, data: bytes, comment: str = "") -> "PublicKey":
        if len(data) != PUBKEY_LEN:
            raise FormatError("public key must be %d bytes" % PUBKEY_LEN)
        return cls(data[:32], data[32:], comment)

    def x25519_object(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(self._x)

    def ed25519_object(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self._ed)

    # ---------------------------------------------------------------- formats

    def to_compact(self) -> str:
        """One-line form, convenient to paste into a chat: ``crsys1...``."""
        body = self.to_bytes()
        checksum = hashlib.sha256(COMPACT_PREFIX.encode() + body).digest()[:4]
        return COMPACT_PREFIX + b64u_e(body + checksum)

    @classmethod
    def from_compact(cls, text: str) -> "PublicKey":
        text = text.strip()
        if not text.startswith(COMPACT_PREFIX):
            raise FormatError("compact key must start with %r" % COMPACT_PREFIX)
        raw = b64u_d(text[len(COMPACT_PREFIX):], "compact key")
        if len(raw) != PUBKEY_LEN + 4:
            raise FormatError("compact key has the wrong length")
        body, checksum = raw[:PUBKEY_LEN], raw[PUBKEY_LEN:]
        expect = hashlib.sha256(COMPACT_PREFIX.encode() + body).digest()[:4]
        if not ct_eq(checksum, expect):
            raise FormatError("compact key checksum mismatch (typo?)")
        return cls.from_bytes(body)

    def to_text(self) -> str:
        fields = [("version", str(_KEYFILE_VERSION)),
                  ("fingerprint", self.fingerprint_hex)]
        if self.comment:
            fields.append(("comment", _sanitize_comment(self.comment)))
        lines = [PUBLIC_BEGIN]
        lines += ["%s: %s" % (k, v) for k, v in fields]
        lines.append("")
        lines.append(wrap_b64(b64e(self.to_bytes())))
        lines.append(PUBLIC_END)
        return "\n".join(lines) + "\n"

    @classmethod
    def from_text(cls, text: str) -> "PublicKey":
        fields, body = _parse_block(text, PUBLIC_BEGIN, PUBLIC_END, "public key")
        key = cls.from_bytes(body, comment=fields.get("comment", ""))
        declared = fields.get("fingerprint")
        if declared and not ct_eq(parse_fingerprint(declared), key.fingerprint):
            raise FormatError("declared fingerprint does not match the key")
        return key

    def save(self, path: str) -> None:
        _atomic_write_text(path, self.to_text())

    @classmethod
    def load(cls, path: str) -> "PublicKey":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_text(fh.read())

    @classmethod
    def parse(cls, value: str) -> "PublicKey":
        """Accept the compact form, an armored block, or a file path.

        Anything unrecognised is tried as a path, so this is the one entry point
        that touches the filesystem with caller-supplied text. Every way that can
        fail is funnelled into :class:`FormatError`: without this, a stray NUL
        byte surfaces as ``ValueError`` and an odd name as ``OSError``, both of
        which escape the error contract callers rely on.
        """
        stripped = value.strip()
        if stripped.startswith(COMPACT_PREFIX):
            return cls.from_compact(stripped)
        if PUBLIC_BEGIN in stripped:
            return cls.from_text(stripped)
        try:
            return cls.load(value)
        except FileNotFoundError:
            raise FormatError(
                "not a CRSYS public key, and no such file: %s" % _describe(value)
            ) from None
        except (OSError, ValueError) as exc:
            raise FormatError(
                "cannot read %s as a public key: %s" % (_describe(value), exc)
            ) from None

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PublicKey) and ct_eq(self.to_bytes(), other.to_bytes())

    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def __repr__(self) -> str:
        return "<PublicKey %s>" % self.fingerprint_hex


class KeyPair:
    """A CRSYS private key (32 bytes X25519 plus a 32-byte Ed25519 seed)."""

    __slots__ = ("_secret", "_x_priv", "_ed_priv", "comment")

    def __init__(self, secret: bytes, comment: str = "") -> None:
        if len(secret) != SECRET_LEN:
            raise FormatError("secret material must be %d bytes" % SECRET_LEN)
        self._secret = secret
        self._x_priv = X25519PrivateKey.from_private_bytes(secret[:32])
        self._ed_priv = Ed25519PrivateKey.from_private_bytes(secret[32:])
        self.comment = comment

    @classmethod
    def generate(cls, comment: str = "") -> "KeyPair":
        return cls(secrets.token_bytes(SECRET_LEN), comment)

    def secret_bytes(self) -> bytes:
        return self._secret

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(
            self._x_priv.public_key().public_bytes_raw(),
            self._ed_priv.public_key().public_bytes_raw(),
            self.comment,
        )

    @property
    def fingerprint(self) -> bytes:
        return self.public_key.fingerprint

    @property
    def fingerprint_hex(self) -> str:
        return self.public_key.fingerprint_hex

    def exchange(self, peer_x25519: bytes) -> bytes:
        """X25519 agreement, with the output validation RFC 9180 requires.

        RFC 9180 section 7.1.4 is explicit: for X25519, recipients MUST check
        whether the shared secret is all-zero and abort if so. That matters here
        because the peer key arrives in a container header an attacker writes,
        and it never passes through :class:`PublicKey`, so the small-order
        blocklist there does not protect this path.

        OpenSSL already refuses those points, so with the current backend this
        check does not fire. It is here anyway: relying on a dependency for a
        requirement the specification places on us is exactly the kind of
        implicit assumption that breaks silently when the backend changes.
        """
        shared = self._x_priv.exchange(X25519PublicKey.from_public_bytes(peer_x25519))
        return check_shared_secret(shared)

    def sign(self, message: bytes) -> bytes:
        return self._ed_priv.sign(message)

    # ---------------------------------------------------------------- formats

    def to_text(self, passphrase: Optional[bytes]) -> str:
        """Serialize the private key, encrypted when a passphrase is given."""
        if passphrase:
            params = kdf.default_params()
            nonce = secrets.token_bytes(NONCE_LEN)
            fields = {
                "version": str(_KEYFILE_VERSION),
                "cipher": "chacha20poly1305",
                "kdf": params.header_value(),
                "salt": kdf.salt_to_text(params.salt),
                "nonce": b64e(nonce),
                "fingerprint": self.fingerprint_hex,
            }
            wrap_key = kdf.derive(passphrase, params)
            aead = aead_for(SUITE_CHACHA20POLY1305, wrap_key)
            body = aead.encrypt(nonce, self._secret, _keyfile_aad(fields))
        else:
            fields = {
                "version": str(_KEYFILE_VERSION),
                "cipher": "none",
                "kdf": "none",
                "salt": "",
                "nonce": "",
                "fingerprint": self.fingerprint_hex,
            }
            body = self._secret

        order = ["version", "cipher", "kdf", "salt", "nonce", "fingerprint"]
        lines = [PRIVATE_BEGIN]
        lines += ["%s: %s" % (k, fields[k]) for k in order if fields[k]]
        if self.comment:
            lines.append("comment: %s" % _sanitize_comment(self.comment))
        lines.append("")
        lines.append(wrap_b64(b64e(body)))
        lines.append(PRIVATE_END)
        return "\n".join(lines) + "\n"

    @classmethod
    def from_text(cls, text: str, passphrase: Optional[bytes] = None) -> "KeyPair":
        fields, body = _parse_block(text, PRIVATE_BEGIN, PRIVATE_END, "private key")
        cipher = fields.get("cipher", "none").strip().lower()
        comment = fields.get("comment", "")

        if cipher == "none":
            key = cls(body, comment)
        elif cipher == "chacha20poly1305":
            if not passphrase:
                raise PassphraseError(
                    "the private key is encrypted: a passphrase is required")
            salt = kdf.salt_from_text(fields.get("salt", ""))
            nonce = b64d(fields.get("nonce", ""), "nonce")
            if len(nonce) != NONCE_LEN:
                raise FormatError("key file nonce has the wrong length")
            params = kdf.KdfParams.parse(fields.get("kdf", ""), salt)
            wrap_key = kdf.derive(passphrase, params)
            aead = aead_for(SUITE_CHACHA20POLY1305, wrap_key)
            try:
                secret = aead.decrypt(nonce, body, _keyfile_aad(fields))
            except InvalidTag as exc:
                raise PassphraseError(
                    "wrong passphrase, or the key file has been modified"
                ) from exc
            key = cls(secret, comment)
        else:
            raise FormatError("unsupported key file cipher: %r" % cipher)

        declared = fields.get("fingerprint")
        if declared and not ct_eq(parse_fingerprint(declared), key.fingerprint):
            raise FormatError("declared fingerprint does not match the private key")
        return key

    def save(self, path: str, passphrase: Optional[bytes] = None) -> bool:
        """Write the private key. Returns whether it could be restricted to you.

        A False result is not a failure to save -- the key is written and
        usable. It means the file's permissions could not be narrowed, which is
        worth telling the user rather than assuming.
        """
        return _atomic_write_text(path, self.to_text(passphrase), private=True)

    @classmethod
    def load(cls, path: str, passphrase: Optional[bytes] = None) -> "KeyPair":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_text(fh.read(), passphrase)

    @staticmethod
    def is_encrypted(path: str) -> bool:
        with open(path, "r", encoding="utf-8") as fh:
            fields, _ = _parse_block(fh.read(), PRIVATE_BEGIN, PRIVATE_END,
                                     "private key")
        return fields.get("cipher", "none").strip().lower() != "none"

    def __repr__(self) -> str:
        return "<KeyPair %s>" % self.fingerprint_hex


# --------------------------------------------------------------------- helpers


def _keyfile_aad(fields: Dict[str, str]) -> bytes:
    canonical = "\n".join("%s=%s" % (k, fields.get(k, "")) for k in _AAD_FIELDS)
    return _KEYFILE_AAD_DOMAIN + canonical.encode("utf-8")


def _sanitize_comment(comment: str) -> str:
    return " ".join(comment.split())[:200]


def _describe(value: str, limit: int = 60) -> str:
    """Quote a caller-supplied value for an error message, bounded and printable."""
    flat = " ".join(value.split())
    if len(flat) > limit:
        flat = flat[:limit] + "..."
    return repr(flat)


def _parse_block(
    text: str, begin: str, end: str, what: str
) -> Tuple[Dict[str, str], bytes]:
    """Strict parser for armored blocks: headers, blank line, base64 body."""
    lines = [ln.rstrip("\r") for ln in text.splitlines()]
    try:
        start = lines.index(begin)
    except ValueError:
        raise FormatError("%s block not found (missing %r)" % (what, begin)) from None
    try:
        stop = lines.index(end, start + 1)
    except ValueError:
        raise FormatError("unterminated %s block (missing %r)" % (what, end)) from None

    fields: Dict[str, str] = {}
    body_lines: List[str] = []
    in_body = False
    for line in lines[start + 1:stop]:
        if not in_body:
            if not line.strip():
                in_body = True
                continue
            key, sep, value = line.partition(":")
            if not sep:
                raise FormatError("malformed header in %s block: %r" % (what, line))
            fields[key.strip().lower()] = value.strip()
        else:
            if line.strip():
                body_lines.append(line.strip())
    if not in_body:
        raise FormatError("missing blank line between headers and body (%s)" % what)
    body = b64d("".join(body_lines), "%s body" % what)
    if not body:
        raise FormatError("empty body in %s block" % what)
    return fields, body


_WINDOWS_SID_CACHE: List[Optional[str]] = []


def _run_hidden(argv, timeout=20):
    # Suppressed below: argv is always a fixed list built here, never
    # shell-parsed and never containing anything a container or a peer
    # supplied. check= is
    # deliberately absent because both callers inspect returncode themselves --
    # _current_user_sid() requires 0 and validates the SID shape, and
    # restrict_to_owner() requires 0 before trusting the new ACL. The one call
    # whose result is ignored is the rollback, where there is nothing better to
    # do than return False.
    return subprocess.run(  # noqa: S603, PLW1510
        argv, capture_output=True, text=True, timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _current_user_sid() -> Optional[str]:
    """The current account's SID, looked up once.

    A SID and not a name: names are ambiguous. On a machine whose hostname
    matches the account name, passing the bare name to icacls resolved to a
    malformed principal, which granted rights to nobody and stripped everyone
    else — locking the owner out of their own private key.
    """
    if _WINDOWS_SID_CACHE:
        return _WINDOWS_SID_CACHE[0]
    sid = None
    try:
        out = _run_hidden(["whoami", "/user", "/fo", "csv", "/nh"], timeout=10)
        if out.returncode == 0:
            fields = [f.strip('" ') for f in out.stdout.strip().split('","')]
            if len(fields) >= 2 and fields[-1].upper().startswith("S-1-"):
                sid = fields[-1]
    except (OSError, subprocess.SubprocessError):
        sid = None
    _WINDOWS_SID_CACHE.append(sid)
    return sid


def restrict_to_owner(path: str) -> bool:
    """Make a file readable only by its owner. Returns whether that succeeded.

    On POSIX this is one chmod. On Windows it is not: ``os.chmod`` there only
    toggles the read-only flag, and the file otherwise keeps whatever the
    containing directory grants — which for a private key is the difference
    between "protected" and "protected in principle".

    Tightening an ACL can lock the owner out, and for a private key that loss is
    not recoverable by the person it happens to. So the new permissions are
    proven by reading the file back, and rolled back if that fails. A key that
    cannot be narrowed is still a usable key; a key nobody can open is not.
    """
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
            return True
        except OSError:
            return False

    if not os.path.exists(path):
        return False
    sid = _current_user_sid()
    if not sid:
        return False
    try:
        applied = _run_hidden(
            ["icacls", path, "/inheritance:r", "/grant:r", "*%s:F" % sid])
        if applied.returncode != 0:
            return False
        with open(path, "rb"):
            pass
        return True
    except (OSError, subprocess.SubprocessError):
        try:
            _run_hidden(["icacls", path, "/reset"])
        except (OSError, subprocess.SubprocessError):
            pass
        return False


def _atomic_write_text(path: str, text: str, private: bool = False) -> bool:
    """Write to a temporary file and rename: never leave a half-written key file.

    Returns whether a private file ended up restricted to its owner.
    """
    directory = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(directory, ".%s.tmp" % os.path.basename(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600 if private else 0o644
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    return restrict_to_owner(path) if private else True


# The eight small-order points of Ed25519, in encoded form. A blocklist is a
# blunt instrument, but the small-order subgroup here has exactly eight elements
# and these are their canonical encodings. The principled check would be
# "[8]A != identity", which needs point arithmetic the library does not expose.
_ED25519_SMALL_ORDER_POINTS = frozenset(
    bytes.fromhex(h) for h in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    )
)


# Small-order points of Curve25519 (RFC 7748 section 6.1). Using one of these as
# a public key forces the shared secret to a known value.
_SMALL_ORDER_POINTS = frozenset(
    {
        bytes(32),
        bytes([1] + [0] * 31),
        bytes.fromhex(
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
        ),
        bytes.fromhex(
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"
        ),
        bytes.fromhex(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        ),
        bytes.fromhex(
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        ),
        bytes.fromhex(
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        ),
        bytes.fromhex(
            "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b8ff"
        ),
        bytes.fromhex(
            "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7"
        ),
        bytes.fromhex(
            "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
        bytes.fromhex(
            "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
        bytes.fromhex(
            "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
    }
)


__all__ = [
    "FPR_LEN",
    "KeyPair",
    "PublicKey",
    "format_fingerprint",
    "parse_fingerprint",
]
