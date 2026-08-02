"""On-disk keyring: a directory holding ``NAME.key`` / ``NAME.pub`` pairs.

Unlocked private keys stay in memory until they are explicitly locked or the
idle timer fires. This is a deliberate trade-off: without a cache every single
operation would cost a passphrase prompt and a full KDF run, and an interface
that asks ten times in a row pushes people towards short passphrases.
"""

from __future__ import annotations

import os
import re
import shutil
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional

from crsys import KeyPair, PublicKey
from crsys._util import ct_eq
from crsys.errors import CrsysError

DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".crsys")

# Names become file names: no path separators, no ".."
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def valid_name(name: str) -> bool:
    return bool(_NAME_RE.match(name or "")) and ".." not in name


@dataclass
class Identity:
    """A keyring entry: public, private, or both."""

    name: str
    pub_path: Optional[str] = None
    key_path: Optional[str] = None
    public_key: Optional[PublicKey] = None
    encrypted: bool = True
    unlocked: bool = False
    error: Optional[str] = None

    @property
    def has_private(self) -> bool:
        return self.key_path is not None

    @property
    def fingerprint(self) -> str:
        return self.public_key.fingerprint_hex if self.public_key else "—"

    @property
    def comment(self) -> str:
        return (self.public_key.comment if self.public_key else "") or ""

    @property
    def label(self) -> str:
        return "%s  ·  %s" % (self.name, self.fingerprint)

    @property
    def kind(self) -> str:
        if self.error:
            return "unreadable"
        if not self.has_private:
            return "public only"
        return "unlocked" if self.unlocked else "private"


class Keyring:
    """Access to the key directory, with a cache of unlocked private keys."""

    def __init__(self, directory: str = DEFAULT_DIR) -> None:
        self.directory = directory
        self._unlocked: Dict[str, KeyPair] = {}
        self._lock = threading.RLock()
        os.makedirs(directory, exist_ok=True)

    # ------------------------------------------------------------------ read

    def scan(self) -> List[Identity]:
        """Re-read the directory. One unreadable file must not hide the others."""
        found: Dict[str, Identity] = {}
        try:
            entries = sorted(os.listdir(self.directory))
        except OSError:
            return []

        for filename in entries:
            stem, ext = os.path.splitext(filename)
            if ext not in (".key", ".pub") or not valid_name(stem):
                continue
            identity = found.setdefault(stem, Identity(name=stem))
            path = os.path.join(self.directory, filename)
            if ext == ".pub":
                identity.pub_path = path
                try:
                    identity.public_key = PublicKey.load(path)
                except (CrsysError, OSError, UnicodeDecodeError) as exc:
                    identity.error = "unreadable public key: %s" % exc
            else:
                identity.key_path = path
                try:
                    identity.encrypted = KeyPair.is_encrypted(path)
                except (CrsysError, OSError, UnicodeDecodeError) as exc:
                    identity.error = "unreadable private key: %s" % exc

        with self._lock:
            for name, identity in found.items():
                keypair = self._unlocked.get(name)
                if keypair is not None:
                    identity.unlocked = True
                    if identity.public_key is None:
                        identity.public_key = keypair.public_key

        return [found[name] for name in sorted(found)]

    def get(self, name: str) -> Optional[Identity]:
        for identity in self.scan():
            if identity.name == name:
                return identity
        return None

    def find_by_public_key(self, public_key: PublicKey) -> Optional[Identity]:
        """Resolve a key to a keyring entry, comparing all 64 bytes.

        This is what must be used before putting a name next to a verified
        signature. Matching on the fingerprint instead would decide identity on
        64 bits, and a 64-bit collision is not out of reach for someone willing
        to grind: the attacker has free choice of the X25519 half, so they can
        search for one whose fingerprint matches a name already in your keyring.
        The fingerprint is for humans to compare out of band, not for the
        software to make a decision on.
        """
        raw = public_key.to_bytes()
        for identity in self.scan():
            if identity.public_key and ct_eq(identity.public_key.to_bytes(), raw):
                return identity
        return None

    def find_by_fingerprint(self, fingerprint: str) -> Optional[Identity]:
        """Look up by fingerprint alone -- a *hint* only.

        Only for cases where a fingerprint is all that exists, such as the
        8-byte recipient hints in a container header. Never use it to attribute
        a signature; use :meth:`find_by_public_key` for that.
        """
        for identity in self.scan():
            if identity.public_key and identity.public_key.fingerprint_hex == fingerprint:
                return identity
        return None

    def public_key(self, name: str) -> PublicKey:
        identity = self.get(name)
        if identity is None or identity.public_key is None:
            raise CrsysError("no public key for %r" % name)
        return identity.public_key

    # ---------------------------------------------------------------- unlock

    def unlock(self, name: str, passphrase: Optional[bytes]) -> KeyPair:
        """Load the private key and cache it. May take ~1 s (KDF)."""
        identity = self.get(name)
        if identity is None or identity.key_path is None:
            raise CrsysError("no private key for %r" % name)
        keypair = KeyPair.load(identity.key_path, passphrase)

        # If the .pub was missing we can rebuild it now that the private key is open.
        if identity.pub_path is None:
            pub_path = os.path.join(self.directory, name + ".pub")
            keypair.public_key.save(pub_path)

        with self._lock:
            self._unlocked[name] = keypair
        return keypair

    def cached(self, name: str) -> Optional[KeyPair]:
        with self._lock:
            return self._unlocked.get(name)

    def is_unlocked(self, name: str) -> bool:
        with self._lock:
            return name in self._unlocked

    def lock(self, name: str) -> None:
        with self._lock:
            self._unlocked.pop(name, None)

    def lock_all(self) -> int:
        with self._lock:
            count = len(self._unlocked)
            self._unlocked.clear()
        return count

    def unlocked_names(self) -> List[str]:
        with self._lock:
            return sorted(self._unlocked)

    # ----------------------------------------------------------------- write

    def create(self, name: str, comment: str, passphrase: Optional[bytes]) -> Identity:
        self._check_free(name)
        keypair = KeyPair.generate(comment=comment)
        key_path = os.path.join(self.directory, name + ".key")
        pub_path = os.path.join(self.directory, name + ".pub")
        keypair.save(key_path, passphrase)
        keypair.public_key.save(pub_path)
        with self._lock:
            self._unlocked[name] = keypair
        return Identity(name, pub_path, key_path, keypair.public_key,
                        encrypted=bool(passphrase), unlocked=True)

    def import_public(self, source: str, name: str) -> Identity:
        """``source`` may be a file path, an armored block, or the compact form."""
        self._check_free(name)
        key = PublicKey.parse(source)
        pub_path = os.path.join(self.directory, name + ".pub")
        key.save(pub_path)
        return Identity(name, pub_path, None, key)

    def import_private(self, path: str, name: str,
                       passphrase: Optional[bytes]) -> Identity:
        """Copy an existing private key in and regenerate its public file."""
        self._check_free(name)
        keypair = KeyPair.load(path, passphrase)
        key_path = os.path.join(self.directory, name + ".key")
        pub_path = os.path.join(self.directory, name + ".pub")
        shutil.copyfile(path, key_path)
        keypair.public_key.save(pub_path)
        with self._lock:
            self._unlocked[name] = keypair
        return Identity(name, pub_path, key_path, keypair.public_key,
                        encrypted=KeyPair.is_encrypted(key_path), unlocked=True)

    def change_passphrase(self, name: str, old: Optional[bytes],
                          new: Optional[bytes]) -> None:
        identity = self.get(name)
        if identity is None or identity.key_path is None:
            raise CrsysError("no private key for %r" % name)
        keypair = KeyPair.load(identity.key_path, old)
        keypair.save(identity.key_path, new)
        with self._lock:
            self._unlocked[name] = keypair

    def delete(self, name: str) -> None:
        identity = self.get(name)
        if identity is None:
            raise CrsysError("identity %r not found" % name)
        for path in (identity.key_path, identity.pub_path):
            if path and os.path.exists(path):
                os.unlink(path)
        self.lock(name)

    def _check_free(self, name: str) -> None:
        if not valid_name(name):
            raise CrsysError(
                "invalid name: use letters, digits, dot, dash and underscore"
            )
        for ext in (".key", ".pub"):
            if os.path.exists(os.path.join(self.directory, name + ext)):
                raise CrsysError("an identity named %r already exists" % name)
