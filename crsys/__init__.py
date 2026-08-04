"""CRSYS -- hybrid public-key encryption.

Typical use::

    from crsys import KeyPair, encrypt_bytes, decrypt_bytes

    alice = KeyPair.generate()
    bob = KeyPair.generate()

    sealed = encrypt_bytes(b"message", recipients=[bob.public_key], signer=alice)
    assert decrypt_bytes(sealed, bob, expected_signer=alice.public_key) == b"message"

The primitives are the standard, well-reviewed ones from the ``cryptography``
library (X25519, Ed25519, HKDF-SHA256, ChaCha20-Poly1305 / AES-256-GCM). What is
specific to CRSYS is the protocol composing them: the container format,
multi-recipient envelopes, STREAM-mode chunking, recipient-bound signatures and
the content key commitment.
"""

from .container import (
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    VERSION,
    Header,
)
from .core import (
    DecryptResult,
    EncryptResult,
    decrypt_bytes,
    decrypt_bytes_verbose,
    decrypt_file,
    decrypt_stream,
    encrypt_bytes,
    encrypt_file,
    encrypt_stream,
    inspect_container,
    sign_detached,
    sign_detached_stream,
    verify_detached,
    verify_detached_stream,
)
from .errors import (
    CrsysError,
    DecryptionError,
    FormatError,
    NoMatchingRecipient,
    PassphraseError,
    SignatureError,
    UnsupportedVersion,
)
from .keys import KeyPair, PublicKey, format_fingerprint, parse_fingerprint
from .suite import (
    SUITE_AES256GCM,
    SUITE_BY_NAME,
    SUITE_CHACHA20POLY1305,
    SUITE_NAMES,
    suite_name,
)

__version__ = "0.2.0"

__all__ = [
    "CrsysError",
    "DecryptResult",
    "DecryptionError",
    "EncryptResult",
    "FormatError",
    "Header",
    "KeyPair",
    "NoMatchingRecipient",
    "PassphraseError",
    "PublicKey",
    "SUITE_AES256GCM",
    "SUITE_BY_NAME",
    "SUITE_CHACHA20POLY1305",
    "SUITE_NAMES",
    "SignatureError",
    "UnsupportedVersion",
    "VERSION",
    "DEFAULT_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "MIN_CHUNK_SIZE",
    "__version__",
    "decrypt_bytes",
    "decrypt_bytes_verbose",
    "decrypt_file",
    "decrypt_stream",
    "encrypt_bytes",
    "encrypt_file",
    "encrypt_stream",
    "format_fingerprint",
    "inspect_container",
    "parse_fingerprint",
    "sign_detached",
    "sign_detached_stream",
    "suite_name",
    "verify_detached",
    "verify_detached_stream",
]
