"""Exception hierarchy for CRSYS."""


class CrsysError(Exception):
    """Base class for every error raised by this package."""


class FormatError(CrsysError):
    """The input is not a well-formed CRSYS container (magic, version, framing)."""


class UnsupportedVersion(FormatError):
    """Container version or cipher suite this build does not implement."""


class DecryptionError(CrsysError):
    """Decryption failed: wrong key, or the file was tampered with or truncated."""


class NoMatchingRecipient(DecryptionError):
    """No envelope in the container can be opened with this private key."""


class SignatureError(DecryptionError):
    """Signature missing, invalid, or from a signer other than the expected one."""


class PassphraseError(CrsysError):
    """Wrong passphrase, or a corrupted private key file."""
